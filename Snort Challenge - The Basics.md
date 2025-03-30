# Snort Challenge - The Basics
---
**Description:** Put your snort skills into practice and write snort rules to analyse live capture network traffic.
**Difficulty:** Medium
**Link**: [https://tryhackme.com/r/room/snortchallenges1]((https://tryhackme.com/r/room/snortchallenges1))
---
## Task 1 - INTRODUCTION

Simply click on the **Start Machine** button to launch the VM you will be using for this task and wait fo it to load.

## Task 2- WRITING IDS RULES (HTTP)

For this task we are provided with two files inside the folder `TASK-2 (HTTP)`.  

```console
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files$ cd TASK-2\ \(HTTP\)/
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ ls
local.rules  mx-3.pcap
```

`local.rules` is the file we need to edit to write our Snort rules and `mx-3.pcap` is a capture file containing the traffic we need to analyse for this task.

**Question 1**
> Navigate to the task folder and use the given pcap file.
>Write a rule to detect all TCP packets from or to port 80.
>What is the number of detected packets you got?
>Note: You must answer this question correctly before answering the rest of the questions.

We're starting off with an easy one.  Open `local.rules` using nano or any othe rtext editor and add the following snort rule:
```yaml
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any 80 <> any any (msg:"Port 80 detected"; sid:100001; rev:1;)
```

Here we are creating an alert that gives us the log entry *"Port 80 detected"* when an incoming or outgoing (`<>`) packet with `any` IP address is coming from or going towards port `80`.

Save and exit the `local.rules` file and run Snort with the following command:
```console
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r mx-3.pcap -c local.rules -l .
```

Here is a breakdown of this command:
- `sudo snort`:  Run snort as Root
- `-r mx-3.pcap`: Load the given network capture file for analysis
- `-c local.rules`: Use the rules found in the provided file
- `-l .`: Output the results to  log file saved in this directory

The answer to thsi question is found at the bottom of the command output under the `Action Stats:` heading:

```console
===============================================================================
Action Stats:
     Alerts:          [REDACTED] ( 35.652%)
     Logged:          [REDACTED] ( 35.652%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
```


**Question 2**
> What is the destination address of packet 63?

To answer this question we can look inside the log file we generated in Question 1 with the following command:
```console
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1743326372 -A full -n 63
```

This time we use `-A full` to specify the output format of the parsed logs and `-n 63` to only process the first 63 packets in the log file.  The answer to this question can be found in the entry for the last packet in the list:

```console
WARNING: No preprocessors configured for policy 0.
05/13-10:17:10.295515 145.254.160.237:3371 -> [REDACTED}:80
TCP TTL:128 TOS:0x0 ID:3917 IpLen:20 DgmLen:761 DF
***AP*** Seq: 0x36C21E28  Ack: 0x2E6B5384  Win: 0x2238  TcpLen: 20
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```


**Question 3**
> What is the ACK number of packet 64?

To answer this question we can simply run the last command again with `-n 64`
```console
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1743326372 -A full -n 64
```

Our answer is in the last packet entry in the output:
```console
WARNING: No preprocessors configured for policy 0.
05/13-10:17:10.295515 145.254.160.237:3371 -> 216.239.59.99:80
TCP TTL:128 TOS:0x0 ID:3917 IpLen:20 DgmLen:761 DF
***AP*** Seq: 0x36C21E28  Ack: [REDACTED]  Win: 0x2238  TcpLen: 20
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

**Question 4**
> What is the SEQ number of packet 62?

OK..so you know what to do by now...rinse and repeat:
```console
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1743326372 -A full -n 62
```

```console
WARNING: No preprocessors configured for policy 0.
05/13-10:17:10.295515 145.254.160.237:3371 -> 216.239.59.99:80
TCP TTL:128 TOS:0x0 ID:3917 IpLen:20 DgmLen:761 DF
***AP*** Seq: [REDACTED]  Ack: 0x2E6B5384  Win: 0x2238  TcpLen: 20
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

**Question 5**
> What is the TTL of packet 65?

```console
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1743326372 -A full -n 65
```

```console
WARNING: No preprocessors configured for policy 0.
05/13-10:17:10.325558 [REDACTED}:[REDACTED] -> 65.208.228.223:80
TCP TTL:[REDACTED] TOS:0x0 ID:3918 IpLen:20 DgmLen:40 DF
***A**** Seq: 0x38AFFFF3  Ack: 0x114C81E4  Win: 0x25BC  TcpLen: 20
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

**Question 6**
> What is the source IP of packet 65?

We can get this from the last packet entry for Question 5


**Question 7**
> What is the source port of packet 65?

We can get this from the last packet entry for Question 5

---
## Task 3- WRITING IDS RULES (FTP)

Now let's move to the folder for TASK 3 and have a look inside:
```console
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ cd ../TASK-3\ \(FTP\)/
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files/TASK-3 (FTP)$ ls
ftp-png-gif.pcap  local.rules
```

Once again we have a `local.rules` file to edit and a network capture to analyse.

**Question 1**
>Write a single rule to detect "all TCP port 21"  traffic in the given pcap.
>
>What is the number of detected packets?

We can tackle this very similarly to TASK 2.  Add the following rule to `local.rules`:
```yaml
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any 21 <> any any (msg: "Port 21 Detected"; sid:100001; rev:1;)
```

Now simply run snort on the given capture file with these rules:
```console
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -r ftp-png-gif.pcap -l .
```

Our answer is found under the *Action Stats* heading of the output:
```console
===============================================================================
Action Stats:
     Alerts:          [REDACTED] ( 72.922%)
     Logged:          [REDACTED] ( 72.922%)
     Passed:            0 (  0.000%)
```

**Question 2**
>Investigate the log file.
>
>What is the FTP service name?

The easiest way to tackle this is to use the `strings` command with `grep` to look for *FTP* in the log file:
```console
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo strings snort.log.1743327826 | grep FTP
}220 [REDACTED] FTP Service
~220 [REDACTED] FTP Service
220 [REDACTED] FTP Service
220 [REDACTED] FTP Service
```

**Question 3**
>**Clear the previous log and alarm files.**
>
>Deactivate/comment on the old rules.
>
>Write a rule to detect failed FTP login attempts in the given pcap.
>
>What is the number of detected packets?


The hint provided with this question tells us that:
>*Each failed FTP login attempt prompts a default message with the pattern; "530 User". Try to filter the given pattern in the inbound FTP traffic.*

So we need to write a rule that looks for packets that include the text *"530 User"* (remember to comment out the previous rule):

```yaml
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
#alert tcp any 21 <> any any (msg: "Port 21 Detected"; sid:100001; rev:1;)
alert tcp any any <> any any (msg:"Failed FTP login attempt";content:"530 User";sid:100001; rev:1;)
```

Now we can run Snort using this updated rule file:
```console
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -r ftp-png-gif.pcap
```

The number of detected packets is near the end of the command output under the heading *Action Stats:*
```console
===============================================================================
Action Stats:
     Alerts:           [REDACTED] (  9.739%)
     Logged:           [REDACTED] (  9.739%)
     Passed:            0 (  0.000%)
```

**Question 4**
>**Clear the previous log and alarm files.**
>
>Deactivate/comment on the old rules.
>
>Write a rule to detect successful FTP logins in the given pcap.
>
>What is the number of detected packets?


This time we are tasked with detecting successful logins, so the process will be the same as for Question 3, but this time we need to match with the pattern *"230 User"* which indicates a successful login.

```console
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
#alert tcp any 21 <> any any (msg: "Port 21 Detected"; sid:100001; rev:1;)
#alert tcp any any <> any any (msg:"Failed FTP login attempt";content:"530 User";sid:100001; rev:1;)
alert tcp any any <> any any (msg:"Failed FTP login attempt";content:"230 User";sid:100001; rev:1;)
```

and run Snort again:
```console
ubuntu@ip-10-10-227-123:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -r ftp-png-gif.pcap
```

And the answer is once again at the bottom of the command output:
```console
===============================================================================
Action Stats:
     Alerts:            [REDACTED] (  0.238%)
     Logged:            [REDACTED] (  0.238%)
     Passed:            0 (  0.000%)
```


