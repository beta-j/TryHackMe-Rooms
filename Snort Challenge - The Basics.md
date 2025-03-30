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
