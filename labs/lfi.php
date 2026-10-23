<?php
// LFI 漏洞页：直接 include 用户传入的文件
$page = isset($_GET['page']) ? $_GET['page'] : 'index.html';
include($page);
?>
