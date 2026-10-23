<?php
// 环境诊断：查看 session 保存路径与 upload_progress 配置
session_start();
echo "session.save_path = " . session_save_path() . "<br>";
echo "upload_progress.enabled = " . ini_get('session.upload_progress.enabled') . "<br>";
echo "upload_progress.cleanup = " . ini_get('session.upload_progress.cleanup') . "<br>";
?>
