# Snort Challenge - Live Attacks
---
**Description:** Put your snort skills into practice and defend against a live attack

**Difficulty:** Medium

**Link**: [https://tryhackme.com/room/snortchallenges2](https://tryhackme.com/room/snortchallenges2)


## CONTENTS
- [Scenario 1 - BRUTE-FORCE](#scenario-1---brute-force)
- [Scenario 2 - REVERSE-SHELL](#scenario-2---reverse-shell)


---
## Scenario 1 - BRUTE-FORCE

>**[+] THE NARRATOR**
>
>J&Y Enterprise is one of the top coffee retails in the world. They are known as tech-coffee shops and serve millions of coffee lover tech geeks and IT specialists every day. 
>
>They are famous for specific coffee recipes for the IT community and unique names for these products. Their top five recipe names are;
>
>**WannaWhite, ZeroSleep, MacDown, BerryKeep** and **CryptoY**.
>
>J&Y's latest recipe, "**Shot4J**", attracted great attention at the global coffee festival. J&Y officials promised that the product will hit the stores in the coming months. 
>
>The super-secret of this recipe is hidden in a digital safe. Attackers are after this recipe, and J&Y enterprises are having difficulties protecting their digital assets.
>
>Last week, they received multiple attacks and decided to work with you to help them improve their security level and protect their recipe secrets.  
>
>
>This is your assistant **J.A.V.A. (Just Another Virtual Assistant)**. She is an AI-driven virtual assistant and will help you notice possible anomalies. Hey, wait, >something is happening...
>
>**[+] J.A.V.A.**
>Welcome, sir. I am sorry for the interruption. It is an emergency. Somebody is knocking on the door!
>
>**[+] YOU**
>Knocking on the door? What do you mean by "knocking on the door"?
>
>**[+] J.A.V.A.**
>We have a brute-force attack, sir.
>
>**[+] THE NARRATOR**
>This is not a comic book! Would you mind going and checking what's going on! Please... 
>
>**[+] J.A.V.A.**
>Sir, you need to observe the traffic with Snort and identify the anomaly first. Then you can create a rule to stop the brute-force attack. GOOD LUCK!

> ---

>First of all, start Snort in sniffer mode and try to figure out the attack source, service and port.
>
>Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!
>
>Here are a few points to remember:
>
>- Create the rule and test it with "-A console" mode. 
>- Use "**-A full**" mode and the **default log path** to stop the attack.
>- Write the correct rule and run the Snort in IPS "-A full" mode.
>- **Block the traffic at least for a minute** and then the flag file will appear on your desktop.
---

Having read through the scenario and the instructions, it's clear that our first course of action should be to start Snort in sniffer mode and try and figure out where the attack is coming from.
We can do this with the following command:
```console
ubuntu:~$ sudo snort -v -l .
```
`-v` enables verbose output and `-l .` outputs the generate log file to the current directory.

Snort will run in the background and we can let it run for a few seconds before interrupting it with Ctrl+C.  

Now we can have a look at generated the log file (I'm using the `-n 30` switch here to limit the output to the first 30 entries:

```console
ubuntu:~$ sudo snort -r snort.log.1743349069 -n 30
```

Most of the traffic appears to be to/from port 80 which indicates that it is regular http traffic.  However there are several packets with a source or destination port 22 which is used for SSH.  This might be worth a closer look.

We can use grep to list all the instances of `:22` in the entire log file:
```console
ubuntu:~$ sudo snort -r snort.log.1743349069 | grep :22
```
![image](https://github.com/user-attachments/assets/90197fc6-8de7-4ff9-8d93-c851439dfe01)

The result shows us a very significant number of packets coming from multiple ports of `10.10.245.36` towards `10.10.140.29` on port 22.  Which could possibly indicate a brute-force attempt.

We can have a closer look at the header of one of these packets using the `-X` switch with snort:

```console
ubuntu:~$ sudo snort -r snort.log.1743349069 -X -n 50
```

```console
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
03/30-15:37:49.833965 10.10.245.36:46672 -> 10.10.140.29:22
TCP TTL:64 TOS:0x0 ID:11396 IpLen:20 DgmLen:136 DF
***AP*** Seq: 0xBC6FA7D3  Ack: 0xA63CE63D  Win: 0x1E1  TcpLen: 32
TCP Options (3) => NOP NOP TS: 1884581438 4119688867 
0x0000: 02 6D 84 B4 B4 1B 02 67 7A 27 40 23 08 00 45 00  .m.....gz'@#..E.
0x0010: 00 88 2C 84 40 00 40 06 78 96 0A 0A F5 24 0A 0A  ..,.@.@.x....$..
0x0020: 8C 1D B6 50 00 16 BC 6F A7 D3 A6 3C E6 3D 80 18  ...P...o...<.=..
0x0030: 01 E1 FE EA 00 00 01 01 08 0A 70 54 6E 3E F5 8D  ..........pTn>..
0x0040: 76 A3 00 00 00 40 F5 0D B1 D3 B5 62 BB FB 8E CF  v....@.....b....
0x0050: E9 58 E8 C5 EE DA 8C BB 0A CA FE D9 DC 38 1D EF  .X...........8..
0x0060: 13 2B 5C EE 84 76 CC CA C0 39 B3 24 71 42 E5 B3  .+\..v...9.$qB..
0x0070: 1E 64 30 87 99 AD 76 AC 5B D8 CC 90 40 DC 0B 81  .d0...v.[...@...
0x0080: D1 29 AD FE 69 CB E3 36 B9 20 7C 14 8F 0F 30 1F  .)..i..6. |...0.
0x0090: 7A 3F 8F CB CB 30                                z?...0

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

From the output we can see that the packet is a TCP packet with SRC IP of `10.10.245.36` and DST IP of `10.10.140.29` and the destination port is `22`.  The source port in this particular packe tis `46672` but there are multiple source ports throughout the capture, so our rule shouldn't be limited to one specific source port.

We now have enough information to write a rule to block this traffic.  To do so we need to edit the `local.rules` file foudn in the `/etc/snort/rules/` directory.
```console
ubuntu:~$ nano /etc/snort/rules/local.rules 
```

Here is the rule I used:
```dircolors
alert tcp 10.10.245.36 any -> any 22 (msg:"SSH attempt from malicious IP"; sid:1000001; rev:1;)
```

The rule works as follows:
- `alert`: creates a log entry when any packets match the rule
- `tcp`: looks for TCP packets
- `10.10.245.36`: coming from any port of 10.10.245.36
- `->`: inbound
- `any 22`: towards port 22 of any IP address

We can test out this rule in console mode:
```console
ubuntu:~$ sudo snort -c /etc/snort/rules/local.rules -A console
```

We can see the Snort log updating live and the alerts coming up whenever a packet matches the rule we created:

![image](https://github.com/user-attachments/assets/12c4421f-6ed1-43b1-8ff5-ac05eaba6670)

We can now go ahead and deploy the rule using the `-A full` switch

```console
ubuntu:~$ sudo snort -c /etc/snort/rules/local.rules -A full
```

We let Snort run for a while and a text file appears on the desktop with our flag for this task.

---

## Scenario 2 - REVERSE-SHELL

>**[+] THE NARRATOR**
>Good Job! Glad to have you in the team!
>
>**[+] J.A.V.A.**
>Congratulations sir. It is inspiring watching you work.
>
>**[+] You**
>Thanks team. J.A.V.A. can you do a quick scan for me? We haven't investigated the outbound traffic yet. 
>
>**[+] J.A.V.A.**
>Yes, sir. Outbound traffic investigation has begun. 
>
>**[+] THE NARRATOR**
>The outbound traffic? Why?
>
>**[+] YOU**
>We have stopped some inbound access attempts, so we didn't let the bad guys get in. How about the bad guys who are already inside? Also, no need to mention the insider risks, huh? The dwell time is still around 1-3 months, and I am quite new here, so it is worth checking the outgoing traffic as well.
>
>**[+] J.A.V.A.**
>Sir, persistent outbound traffic is detected. Possibly a reverse shell...
>
>**[+] YOU**
>You got it!
>
>**[+] J.A.V.A.**
>**Sir, you need to observe the traffic with Snort and identify the anomaly first. Then you can create a rule to stop the reverse shell. GOOD LUCK!**
>
>---
>
>First of all, start Snort in sniffer mode and try to figure out the attack source, service and port.
>
>Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!
>
>Here are a few points to remember:
>
>- Create the rule and test it with "-A console" mode. 
>- Use "**-A full**" mode and the **default log path** to stop the attack.
>- Write the correct rule and run the Snort in IPS "-A full" mode.
>- **Block the traffic at least for a minute** and then the flag file will appear on your desktop.

---

Just like we did for the previous scenario, let's start Snort in sniffer mode and let it run for a while:
```console
ubuntu:~$ sudo snort -v -l .
```

We can now have a log at the log file that was generated
```console
ubuntu:~$ sudo snort -r snort.log.1743351878
```

Scrolling through the ouptut a specific port number immediately pops out amongst the others: port `4444`.  This port is commonly used by reverse-shells such as Metasploit and we know that that's what we're looking for in this scenario!
```console
03/30-16:25:18.062345 10.10.196.55:54148 -> 10.10.144.156:4444
TCP TTL:64 TOS:0x0 ID:3091 IpLen:20 DgmLen:54 DF
***AP*** Seq: 0x7E0E4D82  Ack: 0xB96AF664  Win: 0x1EB  TcpLen: 32
TCP Options (3) => NOP NOP TS: 2358744824 1980912523 
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

We can use the `-d` switch with Snort and the BPF filter `'port 4444`' to look at the payloads of these packets:
```console
ubuntu@ip-10-10-210-31:~$ sudo snort -r snort.log.1743351878 -d 'port 4444'
```

![image](https://github.com/user-attachments/assets/84771d89-d701-48a1-994d-fe39dec828e9)

The results are quite concerning - it looks like the attacker is trying to exfiltrate some data from `10.10.196.55`.

We now have enough information to craft our Snort rule:
- Destination IP: `10.10.144.156`
- Destination Port: `4444`
- Protocol: `TCP`

I decided to create the following two rule entries in `/etc/snort/rules/local.rules`:

```dircolors
alert tcp any 4444 <> any any (msg:"Possible reverse shell on port 4444"; sid:1000001; rev:1;)
alert tcp 10.10.144.156 any <> any any (msg: "Malicious IP detected"; sid:1000002; rev:2;)
```

The first rule should match any traffic to/from port 4444 and flag it as a possible reverse shell, while the second rule will match on any traffic to/from the attacker's IP address.

let's test it out:
```console
ubuntu:~$ sudo snort -c /etc/snort/rules/local.rules -A console
```

Looks like it's working ok!

![image](https://github.com/user-attachments/assets/56519a49-138e-42f4-9a98-cf0e306015ef)

So let's deploy it:
```console
ubuntu:~$ sudo snort -c /etc/snort/rules/local.rules -A full
```
