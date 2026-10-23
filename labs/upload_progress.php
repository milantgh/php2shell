<?php
// 模拟 EOL 旧版 PHP，让扫描器的版本指纹层判定 VULNERABLE
header("X-Powered-By: PHP/5.4.0");
session_start();
echo "php2shell-lab: upload_progress endpoint OK";
?>
