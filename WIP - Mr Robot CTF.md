#### THIS PAGE IS A WORKS IN PROGRESS ####


![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/109cc692-4ce9-4be0-83b8-935211f82301)

# Mr Robot CTF Writeup #
### [https://tryhackme.com/room/adv3nt0fdbopsjcap](https://tryhackme.com/room/mrrobot) ###

#  
### CONTENTS : ###
[TL;DR](#tldr-)

[PROCEDURE](#procedure-)

-  [Part 1 - Retrieving the WiFi SSID](#part-1---retrieving-the-wifi-ssid)
    
-  [Part 2 - Retrieving the WiFi Password](#part-2---retrieving-the-wifi-password)
    
-  [Part 3 - Decrypting and Analysing WiFi Traffic](#part-3---decrypting-and-analysing-wifi-traffic)
    
-  [Part 4 - Decrypting and Replaying a RDP Session](#part-4---decrypting-and-replaying-a-rdp-session)



### TL;DR : ###
#

Target IP: **``10.10.90.47``**

## FLAG 1 of 3 ##

>HINT: `Robots`

We are given a target IP  and a one-word hint that seems to be in-keeping with the overall Mr Robot theme of the room.

To start off, let's perform a NMAP scan just to see what services are running on the target:

```console
root@ip-10-10-140-73:~/mrobot# nmap -sV 10.10.90.47

Starting Nmap 7.60 ( https://nmap.org ) at 2024-02-07 09:03 GMT
Nmap scan report for ip-10-10-90-47.eu-west-1.compute.internal (10.10.90.47)
Host is up (0.00051s latency).
Not shown: 997 filtered ports
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
443/tcp open   ssl/http Apache httpd
MAC Address: 02:14:FF:13:8D:17 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.79 seconds
```

It looks like the server is just running a web-page which we can access by visiting `http://10.10.90.47/` in our browser.  This brings up a cool simulated console:

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/5b168d2c-2a5b-48ba-8b7b-b64f0239b54d)

Trying to enter any of the commands offered on screen doesn't really lead anywhere, other than to give us some cool Mr Robot themed videos, pictures and text prompts. But it's worth noting that every command we enter redirects to a sub-url with the same name.  So for example if we enter the command `inform` it will take us to the `/inform` webpage.

Just as we'd normally do in a normal enumeration exercise (and also because fo that hint we got), we can take a look at the `robots.txt` file to see whether it contains anything interesting:

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/cc7708d5-66c4-415b-8123-a309f57698b8)

From here we can see reference to two interesting files; `fsocity.dic` and `key-1-of-3.txt`.

We can simply look at the contents of `key-1-of-3.txt` by entering the URL `http://10.10.90.47/key-1-of-3.txt` in the browser or by using `curl`:

```console
root@ip-10-10-140-73:~# curl http://10.10.90.47/key-1-of-3.txt
073403<R E D A C T E D>0724b9
```

## FLAG 2 of 3 ##

>Hint: `There's something fishy about this wordlist... Why is it so long?`


We should also go ahead and download a copy of `fsocity.dic`.  Having a look at its contents, it appears to be some kind of wordlist.  Based on past expereinces with similar CTF challenges, this indicates that we'll probably be needing this wordlist to perform a bruteforce password cracking at some point later on.

For the time being, let's take a closer look at the website and see whether we can find an interestiugn directories.  We can use `gobuster` with a small wordlist for this:

```console
root@ip-10-10-140-73:~# gobuster dir -u http://10.10.90.47 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 1000 -q
/license (Status: 200)
/blog (Status: 301)
/sitemap (Status: 200)
/js (Status: 301)
/rss (Status: 301)
/login (Status: 302)
/admin (Status: 301)
```

Interestingly we can see a `/login` page and if we try accessing this we are redirected to `wp-login.php`, which is a Wordpress login page! :)

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/949e60a1-f0b6-494e-9090-01ccdeb9f84e)






