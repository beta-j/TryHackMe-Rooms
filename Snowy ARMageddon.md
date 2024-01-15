### Snowy ARMageddon ###

Victim IP: `10.10.200.123`

Start with a `nmap` scan with the `-sS` switch and go have a coffee while it runs.
The `-sS` switch asks `nmap` to perform a `SYN Stealth scan` which is a relatively stealthy (remember that stealth is important in this challenge) and quick scan.  A `SYN Stealth scan` never opens a full TCP connection and instead relies on sending  `SYN` packets and waiting for a `SYN/ACK` or `RST` responses.

```
sudo nmap -sS -p1-65335 10.10.200.123
```
```
Starting Nmap 7.60 ( https://nmap.org ) at 2024-01-15 09:02 GMT
Nmap scan report for ip-10-10-200-123.eu-west-1.compute.internal (10.10.200.123)
Host is up (0.00029s latency).

PORT      STATE SERVICE
22/tcp    open  ssh
23/tcp    open  telnet
8080/tcp  open  http-proxy
50628/tcp open  unknown
MAC Address: 02:5F:E1:66:EA:0B (Unknown)

```
From the scan results we can see four open ports:
  -  Port `22` for SHH
  - Port `23` for Telnet
  - Port `8080` (most probably a website)
  - Port `50628` - an unusual port number

Connecting via SSH is not possible and we get a `Permission denied (publickey)` error.   Attempting to connect via Telnet successfully establishes a connection which is immediately terminated by the host, and since we don't know anything about port `50628` so far, we're going to ignore it for the time being.

This leaves us with port `8080` and we can just open a browser and navigate to `http://10.10.200.123:8080/` to bring up a website with an angry-looking elf telling us that:



<!--stackedit_data:
eyJoaXN0b3J5IjpbLTM4MjMzNDAyXX0=
-->