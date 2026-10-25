# gigahub-local-dns

Make a **Bell Gigahub** hand out your own DNS server (Pi-hole, AdGuard Home...)
to your devices. The hub's web interface won't accept a LAN address, so this
script uses the hub's API. Single Python file, no dependencies.

Builds on [fernando-granco/Bell-Gigahub-Local-DNS](https://github.com/fernando-granco/Bell-Gigahub-Local-DNS),
adding safety checks, rollback and a fix for the relay lockout.

```bash
curl -O https://raw.githubusercontent.com/gorgalstyan/gigahub-local-dns/main/gigahub_dns.py
python3 gigahub_dns.py                    # show current settings (read-only)
python3 gigahub_dns.py set 192.168.0.50   # hand out your DNS server
python3 gigahub_dns.py revert             # hand out the hub itself again
python3 gigahub_dns.py fix-relay          # point the hub's own DNS back at Bell
```

It asks for the hub's admin password, or reads `GIGAHUB_PASSWORD`. Every change
asks before writing (`-y` skips that). It finds the hub as your computer's
gateway (or asks); use `--router` to set it yourself.

## Don't point the relay at your DNS server

The hub has two DNS settings: **DHCP DNS** (what devices use) and the **relay**
(what the hub itself uses). This script only changes DHCP DNS.

If the relay points at a LAN address, the hub stops routing that address's
traffic: your Pi-hole loses its internet and DNS breaks for the whole network.
A reboot or resetting DNS in the web interface doesn't fix it. `fix-relay` does.

## After switching

- Devices switch when their lease renews, or right away when they reconnect to Wi-Fi.
- Device names like `name.home` only resolve if your DNS server forwards them to
  the hub. In Pi-hole: *Settings → DNS → Conditional forwarding*, e.g. network
  `192.168.0.0/24`, router `192.168.0.1`, domain `home`. `status` warns when this is missing.
- If your DNS server goes down, so does DNS for your devices. Run `revert` to undo.

Tested on a Gigahub 5690, firmware 3.11.6.2.

## License

AGPLv3. The API login is adapted from
[fernando-granco/Bell-Gigahub-Local-DNS](https://github.com/fernando-granco/Bell-Gigahub-Local-DNS).
