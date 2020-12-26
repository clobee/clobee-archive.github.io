# Crack The Hash [THM]

## level 1

### 1. Crack md5

```bash
hash-identifier 48bb6e862e54f2a795ffc4e541caed4d

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

```bash
hashcat --help | grep md5 # Find the hash id

hashcat -m 0 48bb6e862e54f2a795ffc4e541caed4d /usr/share/wordlists/rockyou.txt --show
48bb6e862e54f2a795ffc4e541caed4d:easy
```

### 2. Crack SHA-1

```bash
hash-identifier cbfdac6008f9cab4083784cbd1874f76618d2a97

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))
```

```bash
hashcat --help | grep SHA-1 # Find the hash id

hashcat -m 100 cbfdac6008f9cab4083784cbd1874f76618d2a97 /usr/share/wordlists/rockyou.txt --show
cbfdac6008f9cab4083784cbd1874f76618d2a97:password123
```

### 3. Crack SHA2-256

```bash
hash-identifier 1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032

Possible Hashs:
[+] SHA-256
[+] Haval-256
```

```bash
hashcat --help | grep SHA2-256 # Find the hash id

hashcat -m 1400 1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032 /usr/share/wordlists/rockyou.txt --show
1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032:letmein
```

### 4. Crack bcrypt

[hash-analyzer](https://www.tunnelsup.com/hash-analyzer/) has revealed that we are dealing with bcrypt

```bash
hashcat --help | grep bcrypt # Find the hash id

# Thanks to THM '****' we know the length of the answer 
hashcat -m 3200 -a 3 hash.txt '?l?l?l?l'
$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom:bleh
```
Because this challenge was a bit more involved I had to dig into hashcat options.
I used attack mode 3 now, which corresponds to a brute force attack.
Attack mode 3 takes a single parameter: a mask. 
This tells hashcat the format of the passwords it should attempt.

Each occurrence of ?a will be replaced with a printable ASCII characters (numbers, letters, symbols).
The built-in charsets include:

```bash
    ?l: lowercase letters (a-z)
    ?u: uppercase letters (A-Z)
    ?d: decimal digits (0-9)
    ?h: lowercase hexadecimal digits (0-9, a-f)
    ?H: uppercase hexadecimal digits (0-9, A-F)
    ?s: basic ASCII symbols (e.g., @)
    ?a: printable ASCII characters (numbers, letters, symbols)
    ?b: every possible byte value, from 0x00 to 0xff
```

### 5. Crack md4

https://crackstation.net/ revealed the password `Eternity22` (and a type md4)


```bash 
hash-identifier 279412f945939ba78ce0758d3fd83daa

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

Doing a simple hashcat research didn't yield an exploitable result.
So I used a rule [hashcat rule based](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

```bash
hashcat -m 900 -r /usr/share/hashcat/rules/best64.rule 279412f945939ba78ce0758d3fd83daa /usr/share/wordlists/rockyou.txt --show
279412f945939ba78ce0758d3fd83daa:Eternity22
```

## level 2

### 1. Crack SHA-256

```bash
hash-identifier F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85

Possible Hashs:
[+] SHA-256
[+] Haval-256
```

```bash
hashcat --help | grep SHA2-256 # Find the hash id

hashcat -m 1400 f09edcb1fcefc6dfb23dc3505a882655ff77375ed8aa2d1c13f640fccc2d0c85 /usr/share/wordlists/rockyou.txt --show
f09edcb1fcefc6dfb23dc3505a882655ff77375ed8aa2d1c13f640fccc2d0c85:paule
```

### 2. Crack NTLM

`1DFECA0C002AE40B8619ECF94819CC1B`

I couldn't find the hash type locally using hash-identifier.  
I simply tried https://crackstation.net/ which revealed the password `n63umy8lkf4i` (and a type NTLM)

### 3 Crack sha512crypt

`$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.`

I used [hashcat wiki](https://hashcat.net/wiki/doku.php?id=example_hashes) to find out about the type.
By searching for `$6` in the page I could see that the type was: `sha512crypt $6$, SHA512 (Unix)` and the hash id (for hashcat) is 1800

Unfortunately I couldn't manage to crack this hash using hashcat.
On this one, I used `Jonh The Ripper`

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:05:09 5.26% (ETA: 00:15:41) 0g/s 2792p/s 2792c/s 2792C/s matt70..massaf1
waka99           (?)
```

### 4. Crack hmac-sha1

```bash
hash-identifier e5d8870e5bdd26602cab8dbe07a942c8669e56d6

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))
```

```bash
hashcat --help | grep 'sha1(' # Find the hash id

110 | sha1($pass.$salt)                                | Raw Hash, Salted and/or Iterated
120 | sha1($salt.$pass)                                | Raw Hash, Salted and/or Iterated
...
```

```bash
hashcat -m 110 e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme -a 3 '?a?a?a?a?a?a?a?a?a?a?a?a' /usr/share/wordlists/rockyou.txt --show
```

This command took hours and didn't yield any exploitable result.
I then checked the hint on THM, which was: `HMAC-SHA1`

```bash
hashcat --help | grep -i 'hmac-sha1' # Find the hash id

150 | HMAC-SHA1 (key = $pass)                          | Raw Hash, Authenticated
160 | HMAC-SHA1 (key = $salt)                          | Raw Hash, Authenticated
...
```

```bash
hashcat -m 160 e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme /usr/share/wordlists/rockyou.txt --show
e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme:481616481616
```
