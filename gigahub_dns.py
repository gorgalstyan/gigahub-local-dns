#!/usr/bin/env python3
"""
gigahub_dns.py - check and safely set the DNS a Bell Gigahub hands out over DHCP.

  python3 gigahub_dns.py                   show the hub's DNS settings and check them (read-only)
  python3 gigahub_dns.py set 192.168.0.50  hand out your own DNS server (Pi-hole, AdGuard...) over DHCP
  python3 gigahub_dns.py revert            hand out the hub itself as DNS again
  python3 gigahub_dns.py fix-relay         point the hub's own upstream DNS back at Bell

Every change shows what will happen and asks first (-y skips the question).
Writes are guarded: the script checks the relay is
safe and the new DNS server resolves before writing, watches the relay
afterwards, and rolls back if anything goes wrong.

Why the relay matters: if the hub's DNS relay (its own upstream) points at a LAN
host, the hub stops routing that host's IPv4 traffic. A Pi-hole there loses its
internet and the whole LAN loses DNS. This script only ever changes the DHCP
setting, and fix-relay undoes the damage if something else changed the relay.

Password: prompted, or read from the GIGAHUB_PASSWORD environment variable.
API login adapted from https://github.com/fernando-granco/Bell-Gigahub-Local-DNS (AGPLv3).
"""

import argparse
import getpass
import hashlib
import ipaddress
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DHCP_XPATH = "Device/DHCPv4/Server/Pools/Pool[1]/DNSServers"
RELAY_XPATH = "Device/DNS/Relay/Forwardings/Forwarding[{}]/DNSServer"
RELAY_SLOTS = (1, 2)

BELL_RELAY = ("207.164.234.193", "207.164.234.129")
BLOCKED_TEST_DOMAIN = "doubleclick.net"


# ─── Gigahub API ────────────────────────────────────────────────

class Gigahub:
    """Minimal client for the Gigahub JSON-RPC API. Logs in again if the hub drops a request."""

    NSS = [{"name": "gtw", "uri": "http://sagemcom.com/gateway-data"}]
    OPTIONS = {"nss": NSS, "context-flags": {"get-content-name": True, "local-time": True},
               "capability-depth": 3, "time-format": "ISO_8601",
               "capability-flags": {"name": True, "default-value": True, "restriction": True, "description": True}}

    def __init__(self, host, password):
        self.url = f"http://{host}/cgi/json-req"
        self.pass_hash = hashlib.sha512(password.encode()).hexdigest()
        self.session_id = "0"
        self.ha1 = None
        self.req_id = 0

    def _post(self, body):
        data = urllib.parse.urlencode({"req": json.dumps(body, separators=(",", ":"))}).encode()
        req = urllib.request.Request(self.url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("X-Requested-With", "XMLHttpRequest")
        with urllib.request.urlopen(req, timeout=15) as resp:
            action = json.loads(resp.read().decode())["reply"]["actions"][0]
        desc = action["error"].get("description", "")
        if not desc.endswith("NO_ERR") and action["error"].get("code") not in (16777238, 16777239):
            raise RuntimeError(f"hub error: {desc or action['error']}")
        return action

    def _request(self, actions, ha1):
        cnonce = str(random.randint(0, 2**32 - 1))
        key = hashlib.sha512(f"{ha1}:{self.req_id}:{cnonce}:JSON:/cgi/json-req".encode()).hexdigest()
        body = {"request": {"id": self.req_id, "session-id": self.session_id, "priority": False,
                            "cnonce": cnonce, "auth-key": key, "actions": actions}}
        self.req_id += 1
        return self._post(body)

    def login(self):
        self.session_id, self.req_id = "0", 0
        ha1 = hashlib.sha512(f"admin::{self.pass_hash}".encode()).hexdigest()
        action = self._request([{"id": 0, "method": "logIn", "parameters": {
            "user": "admin", "persistent": "true",
            "session-options": {"nss": self.NSS, "time-format": "ISO_8601", "capability-depth": 2,
                                "context-flags": {"get-content-name": True, "local-time": True},
                                "capability-flags": {"name": True, "default-value": False,
                                                     "restriction": True, "description": False}}}}], ha1)
        params = action["callbacks"][0]["parameters"]
        self.session_id = str(params["id"])
        self.ha1 = hashlib.sha512(f"admin:{params['nonce']}:{self.pass_hash}".encode()).hexdigest()

    def _call(self, action):
        """Send one action; the hub often drops the connection while applying, so re-login and retry."""
        for attempt in range(4):
            try:
                if self.ha1 is None:
                    self.login()
                action["options"] = self.OPTIONS
                return self._request([action], self.ha1)
            except (OSError, urllib.error.URLError, ConnectionError, KeyError) as exc:
                if attempt == 3:
                    raise
                print(f"    (hub dropped the request: {exc.__class__.__name__}; retrying)")
                self.ha1 = None
                time.sleep(3)

    def get(self, xpath):
        return self._call({"id": 0, "method": "getValue", "xpath": xpath})["callbacks"][0]["parameters"]["value"]

    def set(self, xpath, value):
        self._call({"id": 0, "method": "setValue", "xpath": xpath, "parameters": {"value": value}})

    def relay(self):
        return tuple(self.get(RELAY_XPATH.format(s)) for s in RELAY_SLOTS)

    def set_relay(self, servers):
        for slot, server in zip(RELAY_SLOTS, servers):
            self.set(RELAY_XPATH.format(slot), server)


# ─── DNS checks ─────────────────────────────────────────────────

def build_query(name, qid, qtype=1):
    """Return a DNS query packet for `name` (A record by default, 12 for PTR)."""
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)


def parse_reply(reply, qid):
    """Return (rcode, last IPv4 answer or None) from a reply, or None if it isn't ours."""
    if len(reply) < 12 or struct.unpack(">H", reply[:2])[0] != qid:
        return None
    rcode = struct.unpack(">H", reply[2:4])[0] & 0x0F
    answer = None
    if rcode == 0 and struct.unpack(">H", reply[6:8])[0]:
        answer = socket.inet_ntoa(reply[-4:]) if reply[-6:-4] == b"\x00\x04" else True
    return rcode, answer


def query(server, name, timeout, qtype=1):
    """Send one query; return (rcode, answer), or None on no usable reply.

    answer is the last IPv4 address for an A record, True for any other answer, None for none.
    """
    qid = random.randint(0, 0xFFFF)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_query(name, qid, qtype), (server, 53))
        reply, _ = sock.recvfrom(1024)
    except OSError:
        return None
    finally:
        sock.close()
    return parse_reply(reply, qid)


def resolves(server, tries=3, timeout=6.0):
    """True if `server` resolves a random uncached name, which proves its upstream works."""
    for _ in range(tries):
        result = query(server, f"probe{random.randint(10**6, 10**7)}.google.com", timeout)
        if result and result[0] in (0, 3):  # NOERROR or NXDOMAIN
            return True
    return False


def blocks(server):
    """True if `server` answers a well-known ad domain with 0.0.0.0, as Pi-hole and AdGuard do."""
    result = query(server, BLOCKED_TEST_DOMAIN, 4.0)
    return bool(result) and result[1] == "0.0.0.0"


def resolves_local_names(server, router):
    """True/False if `server` can name LAN devices the way the hub can; None if that can't be tested.

    Uses a reverse lookup of this computer's own LAN address, which the hub answers from its leases.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((router, 53))  # no packet sent; just picks the LAN address
        ptr = ipaddress.ip_address(sock.getsockname()[0]).reverse_pointer
        sock.close()
    except OSError:
        return None
    hub = query(router, ptr, 4.0, qtype=12)
    if not (hub and hub[1]):
        return None
    local = query(server, ptr, 4.0, qtype=12)
    return bool(local and local[1])


def default_gateway():
    """This computer's default gateway (Linux or macOS), or None if it can't be found."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.split()
                if fields[1] == "00000000":
                    return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    except OSError:
        pass
    try:
        out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if line.strip().startswith("gateway:"):
                return ip_arg(line.split()[1])
    except (OSError, argparse.ArgumentTypeError):
        pass
    return None


def ip_arg(value):
    """argparse type: reject typos before logging in."""
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an IPv4 address: {value}") from None


def is_lan(address):
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


# ─── Commands ───────────────────────────────────────────────────

def show(hub, router):
    """Print settings and health; return True if nothing is wrong."""
    info = hub.get("Device/DeviceInfo").get("DeviceInfo", {})
    relay = hub.relay()
    servers = [s for s in hub.get(DHCP_XPATH).split(",") if s]
    relay_lan = [s for s in relay if is_lan(s)]
    healthy = not relay_lan

    print(f"Gigahub    {info.get('ModelName', '?')}, firmware {info.get('SoftwareVersion', '?')}")
    print(f"Relay      {', '.join(relay)}" +
          ("   !! LAN address: that host is cut off. Run 'fix-relay'." if relay_lan else "   ok"))
    print(f"DHCP DNS   {', '.join(servers) or '(none)'}")
    for server in servers:
        if server == router:
            print(f"           {server}: the hub itself")
        elif is_lan(server):
            up = resolves(server)
            healthy = healthy and up
            print(f"           {server}: local DNS server, " + ("resolving" if up else "NOT resolving") +
                  (", blocks ads" if up and blocks(server) else ""))
            if up and resolves_local_names(server, router) is False:
                print(f"           note: {server} can't resolve your devices' names (like name.home).")
                print(f"           Turn on Conditional Forwarding in it: network {router.rsplit('.', 1)[0]}.0/24,"
                      f" router {router}, local domain 'home'.")
        else:
            print(f"           {server}: public DNS server")
    if len(servers) > 1 and any(is_lan(s) and s != router for s in servers):
        print("           note: with more than one server, devices can bypass your local DNS server")
    return healthy


def confirm(change, args):
    """Show a planned change and ask; return True to go ahead."""
    print(change)
    if args.yes or input("Apply? [y/N]: ").strip().lower() in ("y", "yes"):
        return True
    print("Cancelled. Nothing changed.")
    return False


def guarded_set_dhcp(hub, servers, args):
    """Write the DHCP DNS setting, watching the relay and rolling back on trouble."""
    value = ",".join(servers)
    relay, before = hub.relay(), hub.get(DHCP_XPATH)
    if any(is_lan(s) for s in relay):
        sys.exit(f"Relay is {', '.join(relay)}, which cuts that host off. Run 'fix-relay' first. Nothing changed.")
    if before == value:
        print(f"DHCP DNS is already {value}. Nothing to do.")
        return
    targets = [s for s in servers if is_lan(s) and s != args.router]
    for server in targets:
        if not resolves(server):
            sys.exit(f"{server} is not resolving right now. Nothing changed.")

    if not confirm(f"DHCP DNS   {before}  ->  {value}", args):
        return

    hub.set(DHCP_XPATH, value)
    for _ in range(6):
        time.sleep(2.5)
        now = hub.relay()
        if now != relay:
            print(f"  !! Hub changed the relay to {', '.join(now)}. Restoring {', '.join(relay)}.")
            hub.set_relay(relay)
            break
    time.sleep(2)

    ok = all(resolves(s) for s in targets)
    if not ok:
        print("The new DNS server stopped resolving. Rolling back...")
        hub.set(DHCP_XPATH, before)
        hub.set_relay(relay)
    print()
    show(hub, args.router)
    if not ok:
        sys.exit("Rolled back to the previous settings.")
    print("\nDone. Devices pick this up when their lease renews, or when they reconnect to Wi-Fi.")


def fix_relay(hub, args):
    current = hub.relay()
    if current == BELL_RELAY:
        print(f"Relay is already {', '.join(current)}. Nothing to do.")
        return
    if not confirm(f"Relay      {', '.join(current)}  ->  {', '.join(BELL_RELAY)}", args):
        return
    hub.set_relay(BELL_RELAY)
    print()
    show(hub, args.router)


def main():
    parser = argparse.ArgumentParser(
        description="Check and safely set the DNS a Bell Gigahub hands out over DHCP.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n\n")[1])
    parser.add_argument("--router", type=ip_arg, help="hub address (default: this computer's gateway)")
    parser.add_argument("-y", "--yes", action="store_true", help="apply changes without asking")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("status", help="show the hub's DNS settings and check them (default, read-only)")
    p_set = sub.add_parser("set", help="hand out these DNS servers over DHCP")
    p_set.add_argument("servers", nargs="+", type=ip_arg,
                       help="one or more IPs; list only your own server so devices can't bypass it")
    sub.add_parser("revert", help="hand out the hub itself as DNS again (the --router address)")
    sub.add_parser("fix-relay", help=f"point the hub's own upstream DNS back at Bell ({', '.join(BELL_RELAY)})")
    args = parser.parse_args()

    if not args.router:
        args.router = default_gateway()
        if args.router:
            print(f"Hub        {args.router} (this computer's gateway; use --router to change)")
        else:
            try:
                args.router = ip_arg(input("Hub address (e.g. 192.168.0.1): ").strip())
            except argparse.ArgumentTypeError as exc:
                sys.exit(str(exc))

    password = os.environ.get("GIGAHUB_PASSWORD") or getpass.getpass("Gigahub admin password: ")
    hub = Gigahub(args.router, password)
    try:
        hub.login()
    except (OSError, RuntimeError, KeyError, ValueError) as exc:
        sys.exit(f"Login failed: {exc} (check the password and --router address)")

    if args.command == "set":
        guarded_set_dhcp(hub, args.servers, args)
    elif args.command == "revert":
        guarded_set_dhcp(hub, [args.router], args)
    elif args.command == "fix-relay":
        fix_relay(hub, args)
    else:
        sys.exit(0 if show(hub, args.router) else 1)


if __name__ == "__main__":
    main()
