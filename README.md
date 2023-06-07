# securlex
securlex.sh - URLsecator bash script for export online/offline hosts from URLhaus CSV file to IPs list(.txt)

```console
$ ./securlex.sh -h

SECURLEX - URLsecator
 Script for export online|offline hosts from URLhaus CSV file to IPs list(.txt).

Usage: securlex.sh [-f<filename>][-t<tags>][-s][-c][-n<Username>][-w<4>][-o fileout.txt]
        -f <filename> - CSV database filename
        -t <tags> - set tags filter / default: 'mirai'
        -s - set filter URLs status to 'online' (optional) / default: 'offline'
        -c - check URLs status; Get HTTP response code (optional) / default: 'off'
        -n <Username> - set URLhaus username filter (optional)
        -w <4> - set cURL timout in sec.(optional) / default: '1' sec.
        -o fileout.txt - set output filename (optional) / default 'offline_mirai_hosts.txt'
        ./securlex.sh -s -f urlhaus.cve -t mirai -n r3dbU7z
```
