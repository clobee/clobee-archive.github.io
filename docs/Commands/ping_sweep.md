# Ping sweep

[Methods for finding the IP address of a downloaded virtual machine · Pentester Land](https://pentester.land/tips-n-tricks/2018/06/26/How-to-get-the-IP-address-of-a-downloaded-vulnerable-machine.html)

### Useful commands

`ifconfig eth1`
`ip addrs`

### Nmap ping sweep

- List all live hosts on the network / Ping scan

```bash
$ nmap -sn -n 10.10.50.*

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-29 23:34 GMT
Nmap scan report for 10.10.50.61
Host is up (0.021s latency).
Nmap scan report for 10.10.50.79
Host is up (0.024s latency).
Nmap scan report for 10.10.50.92
Host is up (0.023s latency).
Nmap scan report for 10.10.50.175
Host is up (0.027s latency).
Nmap scan report for 10.10.50.249
Host is up (0.027s latency).
Nmap done: 256 IP addresses (5 hosts up) scanned in 9.05 seconds
```

```bash
$ nmap -sn -n 10.10.50.1-254

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-29 23:35 GMT
Nmap scan report for 10.10.50.61
Host is up (0.025s latency).
Nmap scan report for 10.10.50.79
Host is up (0.025s latency).
Nmap scan report for 10.10.50.92
Host is up (0.025s latency).
Nmap scan report for 10.10.50.175
Host is up (0.021s latency).
Nmap scan report for 10.10.50.249
Host is up (0.022s latency).
Nmap done: 254 IP addresses (5 hosts up) scanned in 9.05 seconds
```

```bash
$ nmap -sn -n 10.10.50.10/16

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-29 23:38 GMT
Nmap scan report for 10.10.50.61
Host is up (0.025s latency).
Nmap scan report for 10.10.50.79
Host is up (0.025s latency).
Nmap scan report for 10.10.50.92
Host is up (0.025s latency).
Nmap scan report for 10.10.50.175
Host is up (0.021s latency).
Nmap scan report for 10.10.50.249
Host is up (0.022s latency).
...
```

```bash
$ sudo nmap -sS 10.10.50.79,94,160

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-29 23:52 GMT

Nmap scan report for 10.10.50.79
Host is up (0.024s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3389/tcp open  ms-wbt-server


Nmap scan report for 10.10.50.94
Host is up (0.033s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap scan report for 10.10.50.160
Host is up (0.029s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
3389/tcp open  ms-wbt-server
5901/tcp open  vnc-1
6001/tcp open  X11:1
8000/tcp open  http-alt
```

### Netdiscover ping sweep

```bash
$ ip addr show tun0
4: eth1: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    link/none 
    inet 10.14.15.16/16 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::d059:8e62:435b:85e2/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever
```

```bash
netdiscover -P -i eth1 -r 192.168.4.0/24
```
### fping ping sweep

```bash
$ fping -a -g 10.10.50.0/24 2>/dev/null

10.10.50.61
10.10.50.79
10.10.50.92
10.10.50.129
10.10.50.162
10.10.50.175
10.10.50.249
```

### arp-scan ping sweep

```bash
sudo arp-scan 10.10.50.0/24
```

### Custom ping sweep

```bash
$ for x in {78..254..1};do ping -c1 10.10.50.$x|grep "64 b"|cut -d" " -f4 >> ips.txt; done
```

```bash
$ tail -f ips.txt 

10.10.50.79:
```
