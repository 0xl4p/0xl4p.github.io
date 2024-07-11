---
title: "[WRITEUP] Baby Assert - COOKIE ARENA"
categories:
- CTF Writeup
- Cookie Arena
tags:
- Code Injection
- Assert PHP
date: '2024-07-11 14:00:00'
---

## Intro

Link Challenge: [here](https://battle.cookiearena.org/challenges/web/baby-assert){:target="\_blank"}

Mô tả:

```
Trong PHP, có rất nhiều cách để thay thế lệnh điều khiển If Else. 
Tuy nhiên, không phải lập trình viên nào cũng lường trước được những hậu quả nghiêm trọng 
khi sử dụng và thiết lập những tham số an toàn trên môi trường Production.
```

## Exploit
Truy cập `index.php`, có 3 button và chú ý vào url:

![home.php](/assets/img/posts/Baby-Assert-CookieArena/1.png)

Tại url có tham số `?page=` get request tới các trang như home,about và secret. Nhìn bằng mắt thường thì có vẻ như web có thể dính lỗi LFI. Nhưng khi test inject thử '../../../../../etc/passwd' thì có vẻ payload không hoạt động.

- `home.php` có hint 1 đoạn code PHP:

```php
$file = "pages/" . $page . ".php";
assert(...$file...) or die("Detected hacking attempt!");
require_once $file;
```
{: file='home.php'}

- `secret` tiết lộ rằng file flag đã được thêm các kí tự ngẫu nhiên đằng sau. Điều này bắt buộc mình phải **RCE**.

```text
RAND_NAME=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 5 | head -n 1)
FLAG_FILE = /flag$RAND_NAME.txt
```
{: file='secret.php'}

Uhhu, biến `$page` được concat với `$file`. Mà ta có thể thao túng tham số `page` từ request => **Injectable!!**. 

Tuy nhiên, `$file` đã được ném vào 1 hàm gì đó có tên `assert(...$file...)`. 

Tìm hiểu một chút về hàm này thì:
+ **assert()** đơn giản là 1 câu lệnh nhằm mục đích xác nhận một khẳng định là luôn đúng tại đoạn code đó. 
+ **assert()** trả về true thì sẽ pass unit test, ngược lại sẽ fail và ném ra debug.
+ **assert()** về cách hoạt động thì nó tương tự như if-else.
+ Và quan trọng nhất,  **assert()** được PHP ban cho sức mạnh: Nếu mệnh đề trong nó là 1 STRING, nó sẽ coi đó là 1 đoạn mã PHP và thực thi (có vẻ giống `eval`, nực cười nhỉ :))). Đọc thêm tại [How “assertions” can get you Hacked !!](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6){:target="/_blank"}

![Assert RCE??](/assets/img/posts/Baby-Assert-CookieArena/2.png)


Payload:
```
'.system("id").'
```

![Test](/assets/img/posts/Baby-Assert-CookieArena/3.png)

Việc còn lại là đọc flag thôi :v
