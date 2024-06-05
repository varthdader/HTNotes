
def get_recon_template():
    return '''## Target Info-sheet

- DNS-Domain name:
- Host name: INSERTHOSTNAME
- OS:
- Server:
- Kernel:
- Workgroup:
- Windows domain:
---

## Nmap Summary
| Port | Software    | Version                                 | Status  |
| ---- | ----------- | --------------------------------------- | ------- |
| 53   | domain      | Simple DNS                              | open    |
| 80   | http        | Apache http 2.4.29                      | open    |
| 139  | netbios-sec | Microsfot Windows netbios-ssn           | open    |
| 389  | ldap        | Microsoft Windows Active Directory LDAP | open    |


## Information Recon

Ports tcp open in nmap format

```bash

```

Ports services and versions nmap format

```bash

```

Ports UDP nmap format

```bash

```

---
### Playbook Notes:

Prep your attack Surface
```
msfdb run
loadpath /TOOL/Metasploit-Code/modules
workspace "HTB-Labs"
```
#### Recon Playbook

##### Using Legion to Scan All the Things
```
legion
    set workdir /Shared/PyCharms/HTB-Labs/Machines
    set extensions txt,pdf,php,doc,docx,cgi,sh,pl,py,html,htm,phtml
    set host INSERTIPADDRESS
    set domain craft.htb
    run
```

##### Syn-scan
Always start with a stealthy scan to avoid closing ports.
```
db_nmap -sS INSERTIPADDRESS
```
##### Scan all ports, might take a while.
```
db_nmap INSERTIPADDRESS -p-
```
##### Service-version, default scripts, OS:
```
db_nmap INSERTIPADDRESS -sV -sC -O -p 111,222,333
```

##### Scan for UDP
```
db_nmap INSERTIPADDRESS -sU
unicornscan -mU -v -I INSERTIPADDRESS
```

##### Connect to udp if one is open
```
nc -u INSERTIPADDRESS 48772
```
##### Monster scan
```
db_nmap INSERTIPADDRESS -p- -A -T4 -sC
```
##### Not-So-Sneaky Monster Scans
```
db_nmap -sV -sC -Pn -p 1-65535 -T5 --min-rate 1000 --max-retries 5 INSERTIPADDRESS
db_nmap -sU -T4 -p1-1000 -sC -sV INSERTIPADDRESS
masscan -e tun0 -p1-65535,U:1-65535 INSERTIPADDRESS --rate=100
python /TOOL/nosey_neighbour/nosey.py INSERTIPADDRESS
autorecon -o /home/kali/Documents/HTNotes/HTB/Machines/INSERTHOSTNAME/assets/ INSERTIPADDRESS
masscan -e tun0 -p1-65535,U:1-65535 --max-rate=500 INSERTIPADDRESS 
/TOOL/Target-Enumeration/sma.sh
nmap -Pn -n --script vuln INSERTIPADDRESS
```
```button
name Update Machine Playbook
type link
action obsidian://shell-commands/?vault=HTB&execute=28lv9wrf7u
templater true
color green
```


---

'''
    
