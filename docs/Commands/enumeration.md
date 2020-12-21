# Enumeration


## Show OS version

```bash
cat /etc/*release

uname -a 

cat /etc/issue 
```

## Nmap

```bash
# Search for scripts
ls -l /usr/share/nmap/scripts/*ftp*

grep "ftp" /usr/share/nmap/scripts/script.db

# Ping sweep
nmap -sn 192.168.0.1-254 #-sn: no port scan

nmap -sn 192.168.0.0/16

```

## Shares

```bash
#  List the visibles NFS shares
usr/sbin/showmount -e [IP]

# Mount a folder
mkdir /tmp/mount
sudo mount -t nfs [IP]:/home /tmp/mount -nolock

```

## Hydra

```bash
hydra -t 16 -l USERNAME -P /usr/share/wordlists/rockyou.txt -vV 10.10.129.236 ssh

```

## Metasploit

- auxiliary/admin/mysql/mysql_sql
- auxiliary/scanner/mysql/mysql_schemadump
- auxiliary/scanner/mysql/mysql_hashdump

- auxiliary/scanner/smtp/smtp_version
- auxiliary/scanner/smtp/smtp_enum

## Crach ssh key (with john)

```bash
locate ssh2john
python /usr/share/john/ssh2john.py idrsa.id_rsa > my.hash
john --wordlist=/usr/share/wordlists/rockyou.txt my.hash
```

## GPG decrypt

```bash
gpg --import mykey.key
gpg message.gpg
cat message
```

## Hash cracking

1) Find out what encryption is used 

```
$1$	md5crypt, used in Cisco stuff and older Linux/Unix systems
$2$, $2a$, $2b$, $2x$, $2y$	Bcrypt (Popular for web applications)
$6$	sha512crypt (Default for most Linux/Unix systems)
```

or use a site like 
- https://www.tunnelsup.com/hash-analyzer/
- https://hashes.com/en/decrypt/hash

2) Retrieve the encryption code in hashcat
```bash
hashcat -h | grep sha512crypt
```

3) Crack the hash
```bash
hashcat -m 21400 hash.txt /usr/share/wordlists/rockyou.txt
```
