# Ninjaskills [THM](https://tryhackme.com/room/ninjaskills)

__Title__: Ninja Skills  
__Description__:   
__summary__: A basic room to work on the find commands   
__Tags__:  find, find-exec, grep

----

Answer the questions about the following files:

    8V2L
    bny0
    c4ZX
    D8B3
    FHl1
    oiMO
    PFbD
    rmfX
    SRSq
    uqyw
    v2Vb
    X1Uy

The aim is to answer the questions as efficiently as possible.

## Which of the above files are owned by the best-group group(enter the answer separated by spaces in alphabetical order)

```bash
find / -type f -name '????' -group best-group 2>/dev/null
```

## Which of these files contain an IP address?

```bash
find / -type f -name '????' -exec grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" {} \+ 2>/dev/null
```

## Which file has the SHA1 hash of 9d54da7584015647ba052173b84d45e8007eba94

```bash
find / -type f -name "????" -exec sha1sum {} \; 2>/dev/null | grep 9d54da7584015647ba052173b84d45e8007eba94
```

## Which file contains 230 lines?

```bash
wc -l `find / \( -name '8V2L' -o -name 'bny0' -o -name 'c4ZX' -o -name 'D8B3' -o -name 'FHl1' -o -name 'oiMO' -o -name 'PFbD' -o -name 'rmfX' -o -name 'SRSq' -o -name 'uqyw' -o -name 'v2Vb' -o -name 'X1Uy' \) 2>/dev/null` 2>/dev/null | grep 230
```

## Which file's owner has an ID of 502?

```bash
find / -type f -uid 502 -name '????' 2>/dev/null
```

## Which file is executable by everyone?

```bash
find / -type f -executable \( -name '8V2L' -o -name 'bny0' -o -name 'c4ZX' -o -name 'D8B3' -o -name 'FHl1' -o -name 'oiMO' -o -name 'PFbD' -o -name 'rmfX' -o -name 'SRSq' -o -name 'uqyw' -o -name 'v2Vb' -o -name 'X1Uy' \) 2>/dev/null
```