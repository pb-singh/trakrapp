<?php
/**
 * TraKr API Service
 * Secure backend for authentication, sync, and AI proxying.
 */

// 1. Absolute Output Control & Error Suppression
ob_start();
error_reporting(0);
ini_set('display_errors', 0);

// 2. CORS & Security Headers
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
// Allow common local development origins
if (preg_match('/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/', $origin)) {
    header("Access-Control-Allow-Origin: $origin");
}
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

// Handle preflight OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

/**
 * Sends a clean JSON response and terminates execution.
 */
function sendJson($data, $code = 200) {
    while (ob_get_level()) {
        ob_end_clean();
    }
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

// 3. DATABASE CONFIGURATION
if (!defined('DB_TYPE')) define('DB_TYPE', 'mysql'); 
// User Provided Credentials
if (!defined('DB_HOST')) define('DB_HOST', 'localhost');
if (!defined('DB_NAME')) define('DB_NAME', 'filefuse_trakrapp');
if (!defined('DB_USER')) define('DB_USER', 'filefuse_trakrapp');
if (!defined('DB_PASS')) define('DB_PASS', ')kXn_dmPNdLjj*Lp');

function getDbConnection() {
    $strategies = [
        ['host' => DB_HOST, 'port' => 3306, 'user' => DB_USER, 'pass' => DB_PASS, 'dbname' => DB_NAME],
        ['host' => '127.0.0.1', 'port' => 3306, 'user' => 'root', 'pass' => '', 'dbname' => 'trakr_db'],
        ['host' => '127.0.0.1', 'port' => 8889, 'user' => 'root', 'pass' => 'root', 'dbname' => 'trakr_db'],
        ['host' => '127.0.0.1', 'port' => 3306, 'user' => 'root', 'pass' => 'root', 'dbname' => 'trakr_db'],
        ['host' => 'localhost', 'port' => 3306, 'user' => 'root', 'pass' => '', 'dbname' => 'trakr_db'],
    ];

    foreach ($strategies as $cfg) {
        try {
            if (DB_TYPE === 'mysql') {
                $dsn = "mysql:host={$cfg['host']};port={$cfg['port']};dbname={$cfg['dbname']};charset=utf8mb4";
                $pdo = new PDO($dsn, $cfg['user'], $cfg['pass']);
            } else {
                return new PDO('sqlite:' . __DIR__ . '/database.sqlite');
            }
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            return $pdo;
        } catch (PDOException $e) {
            $code = $e->getCode();
            if (DB_TYPE === 'mysql' && $code == 1049 && $cfg['user'] === 'root') {
                try {
                    $dsnNoDb = "mysql:host={$cfg['host']};port={$cfg['port']};charset=utf8mb4";
                    $pdo = new PDO($dsnNoDb, $cfg['user'], $cfg['pass']);
                    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$cfg['dbname']}`");
                    $pdo->exec("USE `{$cfg['dbname']}`");
                    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
                    return $pdo;
                } catch (Exception $ex) {
                    continue;
                }
            }
            continue;
        }
    }
    sendJson(['status' => 'error', 'error' => "Database Connection Failed."], 500);
}

set_exception_handler(function($e) {
    sendJson(['status' => 'error', 'error' => 'Internal Server Error: ' . $e->getMessage()], 500);
});

$pdo = getDbConnection();

// Initial Schema Setup
try {
    if (DB_TYPE === 'mysql') {
        // Added otp_code column
        $pdo->exec("CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(191) UNIQUE, password VARCHAR(255), role VARCHAR(50) DEFAULT 'user', is_premium INT DEFAULT 0, data_json LONGTEXT, otp_code VARCHAR(10) DEFAULT NULL)");
        
        // Migration to add otp_code if missing
        try {
            $pdo->exec("ALTER TABLE users ADD COLUMN otp_code VARCHAR(10) DEFAULT NULL");
        } catch (Exception $e) {} // Ignore if exists

        $pdo->exec("CREATE TABLE IF NOT EXISTS settings (name VARCHAR(191) PRIMARY KEY, value LONGTEXT)");
        $pdo->exec("CREATE TABLE IF NOT EXISTS blocked_ips (ip VARCHAR(100) PRIMARY KEY, reason TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
        $pdo->exec("CREATE TABLE IF NOT EXISTS security_logs (id INT AUTO_INCREMENT PRIMARY KEY, ip VARCHAR(100), event VARCHAR(255), details TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
        $pdo->exec("CREATE TABLE IF NOT EXISTS password_resets (email VARCHAR(191) PRIMARY KEY, code VARCHAR(20), created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    } else {
        $pdo->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user', is_premium INTEGER DEFAULT 0, data_json TEXT, otp_code TEXT DEFAULT NULL)");
        // SQLite Add Column if not exists (Basic check)
        try { $pdo->exec("ALTER TABLE users ADD COLUMN otp_code TEXT DEFAULT NULL"); } catch(Exception $e) {}

        $pdo->exec("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT)");
        $pdo->exec("CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, reason TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
        $pdo->exec("CREATE TABLE IF NOT EXISTS security_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, event TEXT, details TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
        $pdo->exec("CREATE TABLE IF NOT EXISTS password_resets (email TEXT PRIMARY KEY, code TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    }

    $stmt = $pdo->query("SELECT count(*) FROM users");
    if ($stmt->fetchColumn() == 0) {
        $pass = password_hash('admin123', PASSWORD_DEFAULT);
        $pdo->prepare("INSERT INTO users (email, password, role, is_premium) VALUES ('admin@trakr.app', ?, 'admin', 1)")->execute([$pass]);
    }

} catch (Exception $e) {}

// IP Block Check
$ip = $_SERVER['REMOTE_ADDR'];
$stmt = $pdo->prepare("SELECT 1 FROM blocked_ips WHERE ip = ?");
$stmt->execute([$ip]);
if ($stmt->fetch()) {
    sendJson(['status' => 'error', 'error' => 'Access Denied: IP Blocked'], 403);
}

// Start session
session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
]);

$action = $_GET['action'] ?? '';
$input = json_decode(file_get_contents('php://input'), true) ?? [];

// Helper: Get System Config
function getSystemConfig($pdo) {
    $row = $pdo->query("SELECT value FROM settings WHERE name = 'system_config'")->fetch();
    return json_decode($row['value'] ?? '{}', true);
}

// Helper: Send Email (SMTP Fallback)
function sendEmail($to, $subject, $message, $config) {
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $from = $config['smtp_user'] ?? 'noreply@trakr.app';
    $headers .= 'From: <' . $from . '>' . "\r\n";
    
    if (!empty($config['smtp_host'])) {
        ini_set("SMTP", $config['smtp_host']);
        ini_set("smtp_port", $config['smtp_port'] ?? 25);
    }
    
    // Branding
    $logo = $config['email_logo'] ?? '';
    $signature = $config['email_signature'] ?? '';
    
    $htmlContent = '<html><body style="font-family: sans-serif; padding: 20px; color: #333;">';
    if ($logo) {
        $htmlContent .= '<div style="margin-bottom: 25px;"><img src="' . htmlspecialchars($logo) . '" style="max-height: 40px; display: block;"></div>';
    }
    
    $htmlContent .= '<div style="line-height: 1.6; font-size: 16px;">' . $message . '</div>';
    
    if ($signature) {
        $htmlContent .= '<div style="margin-top: 40px; border-top: 1px solid #eee; padding-top: 20px; color: #666; font-size: 14px;">' . nl2br($signature) . '</div>';
    }
    $htmlContent .= '</body></html>';
    
    return mail($to, $subject, $htmlContent, $headers);
}

// --- PUBLIC ACTIONS ---
if ($action === 'get_public_config') {
    $config = getSystemConfig($pdo);
    sendJson(['status' => 'success', 'config' => [
        'google_client_id' => $config['google_client_id'] ?? '',
        'facebook_client_id' => $config['facebook_client_id'] ?? '',
        'onesignal_app_id' => $config['onesignal_app_id'] ?? '',
        'gemini_api_key' => $config['gemini_api_key'] ?? '',
        'premium_title' => $config['premium_title'] ?? 'Pro',
        'premium_features' => $config['premium_features'] ?? ''
    ]]);
}

if ($action === 'login') {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$input['email'] ?? '']);
    $user = $stmt->fetch();
    
    if ($user && password_verify($input['password'] ?? '', $user['password'])) {
        // Generate 2FA Code
        $code = rand(100000, 999999);
        $pdo->prepare("UPDATE users SET otp_code = ? WHERE id = ?")->execute([$code, $user['id']]);
        
        // Send Email
        $config = getSystemConfig($pdo);
        $msg = "Your 2FA Login Code is: <b>$code</b>. Do not share this with anyone.";
        sendEmail($user['email'], "TraKr Login Code", $msg, $config);
        
        sendJson([
            'status' => 'require_otp', 
            'email' => $user['email'],
            'message' => 'Please enter the code sent to your email.'
        ]);
    } else {
        sendJson(['status' => 'error', 'error' => 'Invalid email or password']);
    }
}

if ($action === 'register') {
    $email = $input['email'] ?? '';
    $pass = $input['password'] ?? '';
    if (!$email || !$pass) sendJson(['status' => 'error', 'error' => 'Email and password required']);
    
    // Check if exists
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        sendJson(['status' => 'error', 'error' => 'Email already exists']);
    }

    $hashed = password_hash($pass, PASSWORD_DEFAULT);
    $code = rand(100000, 999999);

    try {
        $stmt = $pdo->prepare("INSERT INTO users (email, password, otp_code) VALUES (?, ?, ?)");
        $stmt->execute([$email, $hashed, $code]);
        
        // Send Verification Email
        $config = getSystemConfig($pdo);
        $msg = "Welcome to TraKr! Your verification code is: <b>$code</b>";
        sendEmail($email, "TraKr Account Verification", $msg, $config);

        sendJson([
            'status' => 'require_otp', 
            'email' => $email,
            'message' => 'Account created. Please check your email for the code.'
        ]);
    } catch (Exception $e) {
        sendJson(['status' => 'error', 'error' => 'Registration failed']);
    }
}

if ($action === 'verify_otp') {
    $email = $input['email'] ?? '';
    $code = $input['code'] ?? '';
    
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? AND otp_code = ?");
    $stmt->execute([$email, $code]);
    $user = $stmt->fetch();
    
    if ($user) {
        // Clear OTP
        $pdo->prepare("UPDATE users SET otp_code = NULL WHERE id = ?")->execute([$user['id']]);
        
        // Login Success
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['role'] = $user['role'];
        
        sendJson([
            'status' => 'success', 
            'user' => [
                'id' => $user['id'], 
                'email' => $user['email'], 
                'role' => $user['role'], 
                'is_premium' => $user['is_premium']
            ]
        ]);
    } else {
        sendJson(['status' => 'error', 'error' => 'Invalid or expired code']);
    }
}

if ($action === 'social_login') {
    $provider = $input['provider'] ?? '';
    $token = $input['token'] ?? '';
    $email = '';
    $name = '';
    $picture = '';

    // Validate Token and Fetch Profile
    if ($provider === 'google') {
        $url = "https://oauth2.googleapis.com/tokeninfo?id_token=$token";
        $json = @file_get_contents($url);
        $data = json_decode($json, true);
        if ($data && isset($data['email'])) {
            $email = $data['email'];
            $name = $data['name'] ?? '';
            $picture = $data['picture'] ?? '';
        }
    } elseif ($provider === 'facebook') {
        $url = "https://graph.facebook.com/me?fields=name,email,picture.type(large)&access_token=$token";
        $json = @file_get_contents($url);
        $data = json_decode($json, true);
        if ($data && isset($data['email'])) {
            $email = $data['email'];
            $name = $data['name'] ?? '';
            $picture = $data['picture']['data']['url'] ?? '';
        }
    }

    if ($email) {
        // Find or Create User
        $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if (!$user) {
            // Create new user with random password
            $pwd = password_hash(bin2hex(random_bytes(8)), PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO users (email, password, role) VALUES (?, ?, 'user')");
            $stmt->execute([$email, $pwd]);
            $uid = $pdo->lastInsertId();
            
            // Fetch again
            $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$uid]);
            $user = $stmt->fetch();
        }

        // Sync Profile Data (Name & Avatar)
        $currentData = json_decode($user['data_json'] ?? '{}', true);
        if (!isset($currentData['profile'])) $currentData['profile'] = [];
        
        $currentData['profile']['name'] = $name ?: ($currentData['profile']['name'] ?? 'User');
        $currentData['profile']['avatar'] = $picture ?: ($currentData['profile']['avatar'] ?? '');
        
        $newDataJson = json_encode($currentData);
        $pdo->prepare("UPDATE users SET data_json = ? WHERE id = ?")->execute([$newDataJson, $user['id']]);
        
        // Update Session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['role'] = $user['role'];

        sendJson(['status' => 'success', 'user' => [
            'id' => $user['id'], 
            'email' => $user['email'], 
            'role' => $user['role'], 
            'is_premium' => $user['is_premium'],
            'synced_profile' => $currentData['profile']
        ]]);
    } else {
        sendJson(['status' => 'error', 'error' => 'Invalid Social Token']);
    }
}

if ($action === 'logout') {
    session_destroy();
    sendJson(['status' => 'success']);
}

// Forgot Password Logic
if ($action === 'forgot_init') {
    $email = $input['email'] ?? '';
    $config = getSystemConfig($pdo);
    
    // Ensure table exists (redundancy for safety)
    try {
        if (DB_TYPE === 'mysql') {
            $pdo->exec("CREATE TABLE IF NOT EXISTS password_resets (email VARCHAR(191) PRIMARY KEY, code VARCHAR(20), created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
        } else {
            $pdo->exec("CREATE TABLE IF NOT EXISTS password_resets (email TEXT PRIMARY KEY, code TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
        }
    } catch (Exception $e) {}

    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        $code = (string)rand(100000, 999999);
        
        if (DB_TYPE === 'mysql') {
            $stmt = $pdo->prepare("REPLACE INTO password_resets (email, code) VALUES (?, ?)");
        } else {
            $stmt = $pdo->prepare("INSERT OR REPLACE INTO password_resets (email, code) VALUES (?, ?)");
        }
        $stmt->execute([$email, $code]);
        
        $subject = "TraKr Password Reset";
        $msg = "Your reset code is: <b>$code</b>";
        sendEmail($email, $subject, $msg, $config);
        
        sendJson(['status' => 'success', 'debug_code' => $code]); 
    }
    sendJson(['status' => 'error', 'error' => 'Email not found']);
}

if ($action === 'forgot_verify') {
    $email = $input['email'] ?? '';
    $code = $input['code'] ?? '';
    $stmt = $pdo->prepare("SELECT * FROM password_resets WHERE email = ? AND code = ?");
    $stmt->execute([$email, $code]);
    if ($stmt->fetch()) {
        sendJson(['status' => 'success']);
    }
    sendJson(['status' => 'error', 'error' => 'Invalid Code']);
}

if ($action === 'forgot_reset') {
    $email = $input['email'] ?? '';
    $code = $input['code'] ?? '';
    $pass = $input['password'] ?? '';
    
    $stmt = $pdo->prepare("SELECT * FROM password_resets WHERE email = ? AND code = ?");
    $stmt->execute([$email, $code]);
    if ($stmt->fetch()) {
        $hashed = password_hash($pass, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE email = ?");
        $stmt->execute([$hashed, $email]);
        
        $pdo->prepare("DELETE FROM password_resets WHERE email = ?")->execute([$email]);
        
        sendJson(['status' => 'success']);
    }
    sendJson(['status' => 'error', 'error' => 'Invalid Request']);
}

// --- AUTHENTICATED ACTIONS ---
if (!isset($_SESSION['user_id'])) {
    if ($action) {
        sendJson(['status' => 'error', 'error' => 'Unauthorized'], 401);
    }
    exit;
}

$userId = $_SESSION['user_id'];

if ($action === 'sync') {
    $forcePull = $input['force_pull'] ?? false;
    if ($forcePull) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $u = $stmt->fetch();
        if ($u) {
            $data = json_decode($u['data_json'] ?? '{}', true);
            sendJson(['status' => 'synced', 'data' => $data]);
        }
    } else {
        $clientData = $input['data'] ?? [];
        $stmt = $pdo->prepare("UPDATE users SET data_json = ? WHERE id = ?");
        $stmt->execute([json_encode($clientData), $userId]);
        sendJson(['status' => 'synced']);
    }
}

if ($action === 'send_otp') {
    $phone = $input['phone'] ?? '';
    // Use passed OTP or generate one (simulation)
    $otp = $input['otp'] ?? rand(1000, 9999); 
    
    $config = getSystemConfig($pdo);
    
    if (!empty($config['whatsapp_api_url']) && !empty($config['whatsapp_auth_key'])) {
        $url = $config['whatsapp_api_url'];
        $url = str_replace('{authkey}', $config['whatsapp_auth_key'], $url);
        $url = str_replace('{phone}', $phone, $url);
        $url = str_replace('{message}', "Your TraKr verification code is $otp", $url);
        
        $ctx = stream_context_create(['http' => ['timeout' => 5]]);
        @file_get_contents($url, false, $ctx);
        
        sendJson(['status' => 'success', 'message' => 'OTP Sent via WhatsApp']);
    }
    
    sendJson(['status' => 'success', 'message' => 'OTP Sent (Simulated)']);
}

if ($action === 'openai_proxy') {
    $config = getSystemConfig($pdo);
    $apiKey = $config['openai_api_key'] ?? '';
    if (!$apiKey) sendJson(['status' => 'error', 'error' => 'OpenAI API Key not configured in admin panel'], 400);

    $endpoint = $input['endpoint'] ?? 'chat'; // chat or audio
    
    $ch = curl_init();
    $headers = [
        'Authorization: Bearer ' . $apiKey
    ];

    if ($endpoint === 'audio') {
        $url = 'https://api.openai.com/v1/audio/transcriptions';
        $base64Audio = $input['audio'] ?? '';
        if (!$base64Audio) sendJson(['status' => 'error', 'error' => 'No audio data']);

        // Decode base64 audio and save to temp file for CURLFile
        $audioData = base64_decode($base64Audio);
        $tempFile = sys_get_temp_dir() . '/temp_audio_' . uniqid() . '.webm';
        file_put_contents($tempFile, $audioData);

        $postFields = [
            'file' => new CURLFile($tempFile, 'audio/webm', 'audio.webm'),
            'model' => 'whisper-1'
        ];
        
        curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge($headers, ['Content-Type: multipart/form-data']));
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postFields);
    } else {
        // Chat (Text or Vision)
        $url = 'https://api.openai.com/v1/chat/completions';
        $payload = $input['payload'] ?? [];
        if (empty($payload)) {
             // Default payload fallback
             $payload = [
                'model' => 'gpt-4o',
                'messages' => [['role' => 'user', 'content' => 'Hello']]
            ];
        }
        
        curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge($headers, ['Content-Type: application/json']));
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    }

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    
    $response = curl_exec($ch);
    
    // Cleanup temp file if audio
    if ($endpoint === 'audio' && isset($tempFile) && file_exists($tempFile)) {
        unlink($tempFile);
    }

    if (curl_errno($ch)) {
         sendJson(['status' => 'error', 'error' => 'OpenAI Request Error: ' . curl_error($ch)]);
    }
    curl_close($ch);
    
    $json = json_decode($response, true);
    sendJson(['status' => 'success', 'data' => $json]);
}

sendJson(['status' => 'error', 'error' => 'Invalid action'], 404);