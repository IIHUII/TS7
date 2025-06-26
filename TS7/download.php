<?php
// Basic security checks
if (!isset($_SERVER['HTTP_HOST'])) {
    die('Direct access not allowed');
}

// Validate inputs
$id = $_GET['id'] ?? '';
$name = $_GET['name'] ?? 'script';
$type = $_GET['type'] ?? 'txt';

if (empty($id) || empty($name) || empty($type)) {
    die('المعطيات غير مكتملة');
}

// More strict input validation
$id = preg_replace('/[^a-zA-Z0-9_-]/', '', $id);
$name = preg_replace('/[^\w\-\.\p{Arabic}]/u', '', $name); // Allows dots in filename
$type = preg_replace('/[^a-zA-Z0-9]/', '', $type);

// Validate path to prevent directory traversal
$base_dir = 'scripts/';
$file_path = $base_dir . $id . '.' . $type;

// Check if path is valid and within allowed directory
$real_base = realpath($base_dir) . DIRECTORY_SEPARATOR;
$real_path = realpath($file_path);

if ($real_path === false || strpos($real_path, $real_base) !== 0) {
    die('الملف غير موجود');
}

if (!file_exists($file_path) || !is_file($file_path)) {
    die('الملف غير موجود');
}

// Set appropriate headers
header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '.' . $type . '"');
header('Expires: 0');
header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
header('Pragma: public');
header('Content-Length: ' . filesize($file_path));

// Clear output buffer and send file
ob_clean();
flush();
readfile($file_path);
exit;
?>
