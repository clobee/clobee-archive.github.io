# Fingerprint


## Grab the server banner

```bash
httprint -P0 -h 10.10.32.245 -s /usr/share/httprint/signatures.txt

httprint v0.301 (beta) - web server fingerprinting tool
(c) 2003-2005 net-square solutions pvt. ltd. - see readme.txt
http://net-square.com/httprint/
httprint@net-square.com

Finger Printing on http://10.10.32.245:80/
Finger Printing Completed on http://10.10.32.245:80/
--------------------------------------------------
Host: 10.10.32.245
Derived Signature:
Apache/2.4.29 (Ubuntu)
9E431BC86ED3C295811C9DC5811C9DC5050C5D32505FCFE84276E4BB811C9DC5
0D7645B5811C9DC5811C9DC5CD37187C11DDC7D7811C9DC5811C9DC52655F350
FCCC535BE2CE6923E2CE6923811C9DC5E2CE6927050C5D336ED3C295811C9DC5
6ED3C295E2CE6926811C9DC5E2CE6923E2CE69236ED3C2956ED3C295E2CE6923
E2CE69236ED3C295811C9DC5E2CE6927E2CE6923

Banner Reported: Apache/2.4.29 (Ubuntu)
Banner Deduced: Apache/2.0.x
Score: 108
Confidence: 65.06
------------------------
Scores: 
Apache/2.0.x: 108 65.06
Apache/1.3.26: 102 52.86
Apache/1.3.27: 101 50.99
Apache/1.3.[4-24]: 100 49.16
Apache/1.3.[1-3]: 100 49.16
TUX/2.0 (Linux): 96 42.25
Microsoft-IIS/6.0: 91 34.54
Apache/1.2.6: 90 33.11
Agranat-EmWeb: 87 29.06
thttpd: 72 13.46
Lotus-Domino/6.x: 71 12.68
WebSitePro/2.3.18: 70 11.92
Netscape-Enterprise/4.1: 67  9.80
Ipswitch-IMail/8.12: 66  9.15
cisco-IOS: 65  8.53
Oracle Servlet Engine: 63  7.35
Netscape-Enterprise/6.0: 62  6.80
MikroTik RouterOS: 62  6.80
Microsoft-IIS/5.0: 61  6.28
Microsoft-IIS/5.0 ASP.NET: 61  6.28
Microsoft-IIS/5.1: 61  6.28
Stronghold/4.0-Apache/1.3.x: 60  5.77
Com21 Cable Modem: 60  5.77
EMWHTTPD/1.0: 59  5.29
RomPager/4.07 UPnP/1.0: 59  5.29
Jetty (unverified): 58  4.84
Apache-Tomcat/4.1.29: 57  4.40
Lexmark Optra Printer: 54  3.23
SMC Wireless Router 7004VWBR: 53  2.88
AOLserver/3.5.6: 52  2.55
dwhttpd (Sun Answerbook): 52  2.55
Microsoft-IIS/4.0: 51  2.23
Netscape-Enterprise/3.6 SP2: 51  2.23
CompaqHTTPServer/1.0: 50  1.94
Intel NetportExpressPro/1.0: 50  1.94
IDS-Server/3.2.2: 50  1.94
Boa/0.94.11: 50  1.94
Belkin Wireless router: 50  1.94
RealVNC/4.0: 50  1.94
JC-HTTPD/1.14.18: 49  1.66
HP-ChaiServer/3.0: 47  1.17
Oracle XML DB/Oracle9i: 27  0.82
Linksys with Talisman firmware: 27  0.82
AssureLogic/2.0: 28  0.82
NetWare-Enterprise-Web-Server/5.1: 29  0.81
Tanberg 880 video conf: 29  0.81
Allied Telesyn Ethernet switch: 25  0.81
WebLogic Server 8.x: 24  0.79
WebLogic Server 8.1: 24  0.79
Jetty/4.2.2: 30  0.79
Microsoft-IIS/URLScan: 23  0.77
CompaqHTTPServer-SSL/4.2: 23  0.77
Netscape-Enterprise/3.6: 22  0.75
Cisco-HTTP: 22  0.75
Cisco Pix 6.2: 22  0.75
Zeus/4.1: 45  0.73
Zeus/4_2: 45  0.73
MiniServ/0.01 Webmin: 45  0.73
fnord: 32  0.73
MiniServ/0.01: 32  0.73
Surgemail webmail (DManager): 32  0.73
AkamaiGHost: 32  0.73
SunONE WebServer 6.0: 21  0.72
Netscape-Enterprise/4.1: 21  0.72
3Com/v1.0: 21  0.72
Tcl-Webserver/3.4.2: 20  0.68
Resin/3.0.8: 19  0.65
Netscape-Enterprise/3.5.1: 34  0.63
Zeus/4.0: 34  0.63
AOLserver/3.4.2-3.5.1: 34  0.63
squid/2.5.STABLE5: 35  0.57
Netscape-Enterprise/3.5.1G: 44  0.54
Jana Server/1.45: 44  0.54
Microsoft-IIS/5.0 Virtual Host: 16  0.52
Xerver_v3: 36  0.50
CompaqHTTPServer/4.2: 36  0.50
WebLogic XMLX Module 8.1: 36  0.50
Lotus-Domino/5.x: 15  0.48
Netgear MR814v2 - IP_SHARER WEB 1.0: 15  0.48
EHTTP/1.1: 14  0.43
Tomcat Web Server/3.2.3: 14  0.43
Adaptec ASM 1.1: 14  0.43
Orion/2.0x: 37  0.41
Microsoft ISA Server (internal): 12  0.34
Microsoft ISA Server (external): 12  0.34
WebSENSE/1.0: 12  0.34
Linksys AP2: 38  0.31
BaseHTTP/0.3 Python/2p3.3 edna/0.4: 38  0.31
Snap Appliances, Inc./3.x: 11  0.30
Ubicom/1.1: 11  0.30
Ubicom/1.1 802.11b: 11  0.30
RemotelyAnywhere: 10  0.25
NetBuilderHTTPDv0.1: 10  0.25
Domino-Go-Webserver/4.6.2.8: 39  0.20
TightVNC: 39  0.20
VisualRoute 2005 Server Edition: 39  0.20
GWS/2.1 Google Web Server: 39  0.20
Linksys WRTP54G: 42  0.20
Linksys Print Server: 8  0.17
Hewlett Packard xjet: 40  0.08
HP Jet-Direct Print Server: 40  0.08
JRun Web Server: 40  0.08
Stronghold/2.4.2-Apache/1.3.x: 41  0.05
Zope/2.6.0 ZServer/1.1b1: 41  0.05
Linksys AP1: 0  0.00
Linksys Router: 0  0.00
ServletExec: 0  0.00
NetPort Software 1.1: 0  0.00
Linksys BEFSR41/BEFSR11/BEFSRU31: 0  0.00
MailEnable-HTTP/5.0: 0  0.00

--------------------------------------------------
```


```bash
openssl s_client -connect 10.10.32.245:80

CONNECTED(00000003)
140106879165696:error:1408F10B:SSL routines:ssl3_get_record:wrong version number:../ssl/record/ssl3_record.c:331:
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 5 bytes and written 283 bytes
Verification: OK
---
New, (NONE), Cipher is (NONE)
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
```

```bash
curl -I 10.10.32.245

HTTP/1.1 200 OK
Date: Thu, 24 Dec 2020 00:39:58 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Sat, 18 Jul 2020 19:09:40 GMT
ETag: "2aa6-5aabc03f3631a"
Accept-Ranges: bytes
Content-Length: 10918
Vary: Accept-Encoding
Content-Type: text/html
```

```bash
sudo nc 10.10.32.245 80
GET /index.html

HTTP/1.1 400 Bad Request
Date: Thu, 24 Dec 2020 00:42:30 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 301
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 127.0.1.1 Port 80</address>
</body></html>
clobee@kali:~/Desktop/tmp$ 

```


