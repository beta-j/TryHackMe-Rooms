# The Return of the Yeti #
## The Yeti needs a plan for 2023. Help him out! ##

>Christmas 2023 is already just around the corner. The Bandit Yeti has been sleeping for most of the year to prepare to hack back into the Best Festival Company. Should he have used that time to plan his attack? Probably. But Yetis need a lot of energy, so don't judge!

This room was included as one of the sidequests for the TryHackMe Advent of Cyber 2023.  We are given [a network capture file; `VanSpy.pcapng`](assets/VanSpy.pcapng) and tasked with answering the following questions:

**NOTE :** All answers to the questions are redacted in this document.  If you'd like to know the answers simply got to the [TryHackMe Room](https://tryhackme.com/room/adv3nt0fdbopsjcap) and follow the steps - it's free 😄

>What's the name of the WiFi network in the PCAP?
>
>What's the password to access the WiFi network?
>
>What suspicious tool is used by the attacker to extract a juicy file from the server?
>
>What is the case number assigned by the CyberPolice to the issues reported by McSkidy?
>
>What is the content of the yetikey1.txt file?


## PROCEDURE : ##

We are given a file called [VanSpy.pcapng](assets/VanSpy.pcapng).  PCAPNG (a.k.a. "PCAP Next Generation", "pcap-ng" or ".pcapng") is a file format for network captures that has some improvements over the regular PCAP files we're accustomed to.  Luckily these files can still be handled by [Wireshark](https://www.wireshark.org/) and we can aslo use it [to convert from one fromat to the other]([url](https://www.netresec.com/?page=Blog&month=2012-12&post=HowTo-handle-PcapNG-files)https://www.netresec.com/?page=Blog&month=2012-12&post=HowTo-handle-PcapNG-files).  so we can go ahead and fire-up Wireshark and start examining the newtwork capture we've been given.

### Part 1 - Retrieving the WiFi SSID ###

For the time being we can't see much as most of the traffic is encrypted, but we can start working towards answering the first couple of questions.  [Aircrack-NG](https://www.aircrack-ng.org/) is an excellent tool for this.  it comes pre-installed with Kali Linux distributions and can be used to analyse network captures and extract valuable information about wifi networks.  however Aircrack-NG does not accept PCAPNG files as its input (yet) - so first we need to convert our PCAPNG to a regular PCAP by going to **File** -> **Save As** in Wireshark and selecting ***Modified tcpdump -pcap*** in the **Save as type:** field and saving the file as `VanSpy.pcap`.  Now we can go to ur Linux terminal and examine the PCAP file with Aircrack-NG:
```
$ aircrack-ng VanSpy.pcap  
Reading packets, please wait...
Opening VanSpy.pcap
Read 45243 packets.

   #  BSSID              ESSID                     Encryption

   1  22:C7:12:C7:E2:35  F*********C               WPA (1 handshake)

Choosing first network as target.

Reading packets, please wait...
Opening VanSpy.pcap
Read 45243 packets.

1 potential targets

Please specify a dictionary (option -w).
```

That's great - from just one (very short) command we already have the answer to teh first question.  The name of the WiFi network is **`F*********C`**.

#  

### Part 2 - Retrieving the WiFi Password ###

Aircrack-NG also makes answering the next question quite simple for us.  Provided that our capture file contains a succesful WiFi handshake in it, we can use the same tool to brute-force and extract the WiFi password.  We'll need to specify a *wordlist* for this command (i.e. a list of words that the program will attempt to use as passwords).  The most propular wordlist to use for such attacks especially CTF challenges is [`rockyou.txt`](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt) which includes some of the most commonly used passwords.
```
$ aircrack-ng VanSpy.pcap -w /usr/share/wordlists/rockyou.txt
```

After just a couple of seconds Aircrack-NG has retrieved the WiFi password for us:
```
                               Aircrack-ng 1.7 

      [00:00:18] 31526/14344392 keys tested (1726.75 k/s) 

      Time left: 2 hours, 18 minutes, 8 seconds                  0.22%

                           KEY FOUND! [ C******** ]


      Master Key     : C4 BB 8C DA 66 C3 72 E6 C2 86 14 84 6E 2B 03 EC 
                       3D 00 2E A7 DE 31 96 BA 86 3A 47 4D 63 3A 48 75 

      Transient Key  : B2 F3 33 91 8A 56 EA 1C 5F BA 8A D7 19 9D A4 62 
                       BA 0A CE C1 46 85 AC 59 4D 38 EA 60 BD D2 88 0B 
                       6A 21 CD 84 B1 A5 07 EA 8F 8B B7 17 B7 DF F4 A2 
                       D8 F3 61 53 32 87 A0 0D 87 78 38 A3 C4 60 E9 B6 

      EAPOL HMAC     : AA CD A8 56 3F 4B AC 08 C8 B1 B8 74 0B 52 2E 6C 
```

So to answer the second question, the WiFi password is **`C********`**

#  
### Part 3 - Decrypting WiFi Traffic ###

Now that we have a WiFi password we're going to need to decrypt the WiFi traffic in the network capture to be able to continue our investigation further.  To do this in Wireshark go to **Edit** > **Preferences** > **Protocols** > **IEEE 802.11** and click on the **Edit** button next to *Decryption Keys*.  Click on the `+` sign at the bottom left corner and select *Key type* : `wpa-pwd` and enter the password in the format `password:SSID`.  So in our case this will be `C********:F*********C`. Then click on **OK**.

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/42718960-4238-4466-af1d-6f92b2586ba8)



