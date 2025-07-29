<?php 

session_start();
require_once 'config/db.php';

if (isset($_POST['signin'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];

    if (empty($email)) {
        $_SESSION['error'] = 'กรุณากรอก Email';
        header("location: signin.php");
    } else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['error'] = 'รูปแบบ Email ไม่ถูกต้อง';
        header("location: signin.php");
    } else if (empty($password)) {
        $_SESSION['error'] = 'กรุณากรอก รหัสผ่าน';
        header("location: signin.php");
    } else if (strlen($password) > 20 || strlen($password) < 5) {
        $_SESSION['error'] = 'รหัสต้องมีความยาวระหว่าง 5ถึง 20 ตัวอักษร';
        header("location: signin.php");
    } else {
        try {
            
            $check_data = $conn->prepare("SELECT * FROM users WHERE email = :email");
            $check_data->bindParam(":email", $email);
            $check_data->execute();
            $row = $check_data->fetch(PDO::FETCH_ASSOC);

            if ($check_data->rowCount() > 0) {
                // เช็คว่าข้อมูลที่ได้มาตรงกับ email ที่ป้อน
                if ($email == $row['email']) {
                    if (password_verify($password, $row['password'])) {
                        if ($row['urole'] == 'admin') {
                            $_SESSION['admin_login'] = $row['id'];
                            header("location: admin.php");
                        } else {
                            $_SESSION['user_login'] = $row['id'];
                            header("location: user.php");
                        }
                    } else {
                        $_SESSION['error'] = 'รหัสผ่านไม่ถูกต้อง';
                        header("location: signin.php");
                    }
                } else {
                    $_SESSION['error'] = 'อีเมลไม่ตรงกับข้อมูล';
                    header("location: signin.php");
                }
            } else {
                $_SESSION['error'] = "ไม่พบข้อมูลอีเมลนี้ในระบบ";
                header("location: signin.php");
            }

        } catch(PDOException $e) {
            echo $e->getMessage();
        }
    }
}
?>
