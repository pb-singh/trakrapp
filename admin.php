<?php
/**
 * TraKr Admin Panel
 * Secure management for users, logs, blocked IPs, and system configuration.
 */

// --- DATABASE CONFIGURATION (Matches api.php) ---
if (!defined('DB_TYPE')) define('DB_TYPE', 'mysql'); 
// User Provided Credentials
if (!defined('DB_HOST')) define('DB_HOST', 'localhost');
if (!defined('DB_NAME')) define('DB_NAME', 'filefuse_trakrapp');
if (!defined('DB_USER')) define('DB_USER', 'filefuse_trakrapp');
if (!defined('DB_PASS')) define('DB_PASS', ')kXn_dmPNdLjj*Lp');

function getDbConnection() {
    // 1. Primary Strategy: User Configured Credentials
    // 2. Fallbacks: Localhost/XAMPP/MAMP defaults (in case code is moved to local dev)
    $strategies = [
        ['host' => DB_HOST, 'port' => 3306, 'user' => DB_USER, 'pass' => DB_PASS, 'dbname' => DB_NAME],
        ['host' => '127.0.0.1', 'port' => 3306, 'user' => 'root', 'pass' => '', 'dbname' => 'trakr_db'],
        ['host' => '127.0.0.1', 'port' => 8889, 'user' => 'root', 'pass' => 'root', 'dbname' => 'trakr_db'],
        ['host' => '127.0.0.1', 'port' => 3306, 'user' => 'root', 'pass' => 'root', 'dbname' => 'trakr_db'],
        ['host' => 'localhost', 'port' => 3306, 'user' => 'root', 'pass' => '', 'dbname' => 'trakr_db'],
    ];

    $lastError = '';

    foreach ($strategies as $cfg) {
        try {
            if (DB_TYPE === 'mysql') {
                $dsn = "mysql:host={$cfg['host']};port={$cfg['port']};dbname={$cfg['dbname']};charset=utf8mb4";
                $pdo = new PDO($dsn, $cfg['user'], $cfg['pass']);
            } else {
                return new PDO('sqlite:' . __DIR__ . '/database.sqlite');
            }
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            return $pdo;
        } catch (PDOException $e) {
            $lastError = $e->getMessage();
            $code = $e->getCode();

            // Only attempt to create database if we are using local root credentials
            // Shared hosting credentials usually don't have CREATE DATABASE permissions
            if (DB_TYPE === 'mysql' && $code == 1049 && $cfg['user'] === 'root') {
                try {
                    $dsnNoDb = "mysql:host={$cfg['host']};port={$cfg['port']};charset=utf8mb4";
                    $pdo = new PDO($dsnNoDb, $cfg['user'], $cfg['pass']);
                    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$cfg['dbname']}`");
                    $pdo->exec("USE `{$cfg['dbname']}`");
                    return $pdo;
                } catch (Exception $ex) {
                    continue;
                }
            }

            // Connection failed, try next strategy
            continue;
        }
    }

    // If loop finishes without returning, all strategies failed.
    die("Database Connection Failed. <br>Last Error: $lastError");
}

ob_start();
session_start();
ini_set('display_errors', 0);

function sendJson($data) {
    while (ob_get_level()) ob_end_clean();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data);
    exit;
}

$pdo = getDbConnection();
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

// Role Protection
$isAdmin = isset($_SESSION['role']) && $_SESSION['role'] === 'admin';

if (isset($_GET['api'])) {
    if (!$isAdmin) sendJson(['status' => 'error', 'error' => 'Unauthorized']);

    $action = $_GET['api'];
    
    // List of secrets to mask/protect
    $secrets = [
        'openai_api_key', 'gemini_api_key', 
        'smtp_pass', 'onesignal_rest_key', 'whatsapp_auth_key',
        'google_client_secret', 'facebook_client_secret'
    ];
    
    if ($action === 'get_data') {
        $users = $pdo->query("SELECT id, email, role, is_premium FROM users ORDER BY id DESC")->fetchAll();
        $logs = $pdo->query("SELECT * FROM security_logs ORDER BY created_at DESC LIMIT 50")->fetchAll();
        $blocked = $pdo->query("SELECT * FROM blocked_ips ORDER BY created_at DESC")->fetchAll();
        $row = $pdo->query("SELECT value FROM settings WHERE name = 'system_config'")->fetch();
        $config = json_decode($row['value'] ?? '{}', true);
        
        // Mask secrets
        foreach ($secrets as $key) {
            if (!empty($config[$key])) {
                $config[$key] = '********' . substr($config[$key], -4);
            }
        }

        sendJson(['status' => 'success', 'data' => [
            'users' => $users,
            'logs' => $logs,
            'blocked' => $blocked,
            'config' => $config
        ]]);
    }

    if ($action === 'save_config') {
        $input = json_decode(file_get_contents('php://input'), true);
        $row = $pdo->query("SELECT value FROM settings WHERE name = 'system_config'")->fetch();
        $existing = json_decode($row['value'] ?? '{}', true);
        
        // Preserve secrets if not changed (if value contains '****')
        foreach ($secrets as $key) {
            if (isset($input[$key]) && strpos($input[$key], '****') !== false) {
                $input[$key] = $existing[$key] ?? '';
            }
        }

        // Save
        if (DB_TYPE === 'mysql') {
            $stmt = $pdo->prepare("INSERT INTO settings (name, value) VALUES ('system_config', ?) ON DUPLICATE KEY UPDATE value = VALUES(value)");
            $stmt->execute([json_encode($input)]);
        } else {
            $stmt = $pdo->prepare("INSERT OR REPLACE INTO settings (name, value) VALUES ('system_config', ?)");
            $stmt->execute([json_encode($input)]);
        }
        
        // Log action
        $logStmt = $pdo->prepare("INSERT INTO security_logs (ip, event, details) VALUES (?, 'config_update', 'System configuration updated')");
        $logStmt->execute([$_SERVER['REMOTE_ADDR']]);

        sendJson(['status' => 'success']);
    }

    if ($action === 'block_ip') {
        $input = json_decode(file_get_contents('php://input'), true);
        $ip = $input['ip'] ?? '';
        $reason = $input['reason'] ?? 'Manual Block';
        if ($ip) {
            if (DB_TYPE === 'mysql') {
                $stmt = $pdo->prepare("INSERT IGNORE INTO blocked_ips (ip, reason) VALUES (?, ?)");
            } else {
                $stmt = $pdo->prepare("INSERT OR IGNORE INTO blocked_ips (ip, reason) VALUES (?, ?)");
            }
            $stmt->execute([$ip, $reason]);
            
            // Log
            $pdo->prepare("INSERT INTO security_logs (ip, event, details) VALUES (?, 'manual_block', ?)")->execute([$_SERVER['REMOTE_ADDR'], "Blocked IP: $ip"]);
            
            sendJson(['status' => 'success']);
        }
        sendJson(['status' => 'error', 'error' => 'Invalid IP']);
    }

    if ($action === 'unblock_ip') {
        $input = json_decode(file_get_contents('php://input'), true);
        $ip = $input['ip'] ?? '';
        if ($ip) {
            $stmt = $pdo->prepare("DELETE FROM blocked_ips WHERE ip = ?");
            $stmt->execute([$ip]);
            
            // Log
            $pdo->prepare("INSERT INTO security_logs (ip, event, details) VALUES (?, 'manual_unblock', ?)")->execute([$_SERVER['REMOTE_ADDR'], "Unblocked IP: $ip"]);
            
            sendJson(['status' => 'success']);
        }
        sendJson(['status' => 'error', 'error' => 'Invalid IP']);
    }
    exit;
}

if (!$isAdmin):
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8"><title>TraKr Admin Access</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="icon" href="assets/trakr-logo.png" type="image/png">
</head>
<body class="bg-slate-950 text-white h-screen flex items-center justify-center">
    <div class="text-center p-8 bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl">
        <div class="w-16 h-16 bg-red-500/10 text-red-500 rounded-full flex items-center justify-center mx-auto mb-6">
            <i class="fa-solid fa-lock text-3xl"></i>
        </div>
        <h1 class="text-2xl font-bold mb-4">Restricted Access</h1>
        <p class="text-slate-400 mb-6">Administrator session not detected. Please login via the main app.</p>
        <a href="index.html" class="inline-block px-6 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg font-bold transition-colors">Back to App</a>
    </div>
</body>
</html>
<?php exit; endif; ?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8"><title>TraKr | Management Console</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.13.3/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="icon" href="assets/trakr-logo.png" type="image/png">
    <style>[x-cloak] { display: none !important; } .custom-scrollbar::-webkit-scrollbar { width: 4px; } .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }</style>
</head>
<body class="bg-slate-950 text-slate-100 font-sans" x-data="adminApp()" x-init="init()" x-cloak>
    <div class="flex h-screen">
        <aside class="w-64 bg-slate-900 border-r border-slate-800 p-6 flex flex-col">
            <div class="flex items-center gap-3 mb-10">
                <img src="assets/trakr-logo.png" class="w-8">
                <h1 class="font-bold text-xl">TraKr Admin</h1>
            </div>
            <nav class="flex-1 space-y-2">
                <button @click="tab = 'users'" :class="tab === 'users' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:bg-slate-800'" class="w-full text-left p-3 rounded-xl transition-all font-medium"><i class="fa-solid fa-users w-6"></i> User Base</button>
                <button @click="tab = 'blocked'" :class="tab === 'blocked' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:bg-slate-800'" class="w-full text-left p-3 rounded-xl transition-all font-medium"><i class="fa-solid fa-ban w-6"></i> Blocked IPs</button>
                <button @click="tab = 'config'" :class="tab === 'config' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:bg-slate-800'" class="w-full text-left p-3 rounded-xl transition-all font-medium"><i class="fa-solid fa-sliders w-6"></i> System Config</button>
                <button @click="tab = 'logs'" :class="tab === 'logs' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:bg-slate-800'" class="w-full text-left p-3 rounded-xl transition-all font-medium"><i class="fa-solid fa-file-shield w-6"></i> Audit Logs</button>
            </nav>
            <button @click="logout" class="mt-auto text-red-500 font-bold hover:bg-red-500/10 p-3 rounded-xl transition-colors flex items-center justify-center gap-2">
                <i class="fa-solid fa-sign-out"></i> Sign Out
            </button>
        </aside>

        <main class="flex-1 overflow-y-auto p-10 custom-scrollbar">
            <!-- USERS TAB -->
            <div x-show="tab === 'users'" class="space-y-6">
                <h2 class="text-3xl font-bold">User Management</h2>
                <div class="bg-slate-900 rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
                    <table class="w-full text-left">
                        <thead class="bg-slate-800 text-xs font-bold uppercase text-slate-500"><tr><th class="p-4">Email</th><th class="p-4">Role</th><th class="p-4">Tier</th></tr></thead>
                        <tbody>
                            <template x-for="u in users">
                                <tr class="hover:bg-slate-800/50 transition-colors">
                                    <td class="p-4 border-t border-slate-800 flex items-center gap-3">
                                        <div class="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center text-slate-400"><i class="fa-solid fa-user"></i></div>
                                        <span x-text="u.email"></span>
                                    </td>
                                    <td class="p-4 border-t border-slate-800"><span class="px-2 py-1 rounded text-xs font-bold uppercase" :class="u.role === 'admin' ? 'bg-indigo-500/20 text-indigo-400' : 'bg-slate-800 text-slate-400'" x-text="u.role"></span></td>
                                    <td class="p-4 border-t border-slate-800" x-text="u.is_premium ? 'Premium' : 'Free'"></td>
                                </tr>
                            </template>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- BLOCKED IPS TAB -->
            <div x-show="tab === 'blocked'" class="space-y-6">
                <div class="flex justify-between items-center">
                    <h2 class="text-3xl font-bold">Blocked IP Management</h2>
                    <div class="flex gap-2">
                        <input type="text" x-model="newBlockIp" placeholder="IP Address" class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500">
                        <button @click="blockIp" class="bg-red-600 hover:bg-red-500 px-4 py-2 rounded-lg text-sm font-bold transition-colors">Block</button>
                    </div>
                </div>
                <div class="bg-slate-900 rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
                    <table class="w-full text-left">
                        <thead class="bg-slate-800 text-xs font-bold uppercase text-slate-500">
                            <tr><th class="p-4">IP Address</th><th class="p-4">Reason</th><th class="p-4">Blocked At</th><th class="p-4">Actions</th></tr>
                        </thead>
                        <tbody>
                            <template x-for="b in blocked">
                                <tr>
                                    <td class="p-4 border-t border-slate-800 font-mono text-sm text-red-400" x-text="b.ip"></td>
                                    <td class="p-4 border-t border-slate-800" x-text="b.reason || 'Manual Block'"></td>
                                    <td class="p-4 border-t border-slate-800 text-slate-400 text-sm" x-text="b.created_at"></td>
                                    <td class="p-4 border-t border-slate-800">
                                        <button @click="unblockIp(b.ip)" class="text-emerald-400 hover:text-emerald-300 font-bold text-xs uppercase bg-emerald-500/10 px-3 py-1.5 rounded-lg border border-emerald-500/20">Unblock</button>
                                    </td>
                                </tr>
                            </template>
                            <tr x-show="blocked.length === 0"><td colspan="4" class="p-8 text-center text-slate-500 italic">No blocked IPs found.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- CONFIG TAB -->
            <div x-show="tab === 'config'" class="space-y-6">
                <div class="flex justify-between items-center">
                    <h2 class="text-3xl font-bold">System Configuration</h2>
                    <button @click="saveConfig" class="px-6 py-2 bg-indigo-600 rounded-xl font-bold hover:bg-indigo-500 transition-all shadow-lg shadow-indigo-600/20 flex items-center gap-2">
                        <i class="fa-solid fa-save"></i> Save Changes
                    </button>
                </div>
                
                <div class="grid grid-cols-1 xl:grid-cols-2 gap-6">
                    <!-- General Settings -->
                    <div class="bg-slate-900 p-6 rounded-2xl border border-slate-800 space-y-4">
                        <h3 class="text-lg font-bold text-white border-b border-slate-800 pb-2 mb-4"><i class="fa-solid fa-rocket text-indigo-500 mr-2"></i> General & Security</h3>
                        
                        <!-- 2FA Toggle -->
                        <div class="flex items-center justify-between p-4 bg-slate-950 rounded-xl border border-slate-800">
                            <div>
                                <p class="font-bold text-sm">Two-Factor Authentication (2FA)</p>
                                <p class="text-xs text-slate-500">Require email OTP for all logins and registrations.</p>
                            </div>
                            <button @click="config.enable_2fa = !config.enable_2fa" :class="config.enable_2fa ? 'bg-indigo-600' : 'bg-slate-800'" class="w-12 h-6 rounded-full relative transition-all">
                                <div class="w-4 h-4 bg-white rounded-full absolute top-1 transition-all" :class="config.enable_2fa ? 'left-7' : 'left-1'"></div>
                            </button>
                        </div>

                        <div>
                            <label class="block text-xs font-bold uppercase text-slate-500 mb-2">Gemini API Key (Frontend)</label>
                            <input type="password" x-model="config.gemini_api_key" placeholder="AIza..." class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500 transition-colors">
                        </div>
                        <div>
                            <label class="block text-xs font-bold uppercase text-slate-500 mb-2">OpenAI API Key (Proxy)</label>
                            <input type="password" x-model="config.openai_api_key" placeholder="sk-..." class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500 transition-colors">
                        </div>
                    </div>

                    <!-- Social Login -->
                    <div class="bg-slate-900 p-6 rounded-2xl border border-slate-800 space-y-4">
                        <h3 class="text-lg font-bold text-white border-b border-slate-800 pb-2 mb-4"><i class="fa-solid fa-users text-blue-500 mr-2"></i> Social Login</h3>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-bold uppercase text-slate-500 mb-2">Google Client ID</label>
                                <input type="text" x-model="config.google_client_id" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500 transition-colors">
                            </div>
                            <div>
                                <label class="block text-xs font-bold uppercase text-slate-500 mb-2">Google Client Secret</label>
                                <input type="password" x-model="config.google_client_secret" placeholder="Secret..." class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500 transition-colors">
                            </div>
                            <div>
                                <label class="block text-xs font-bold uppercase text-slate-500 mb-2">Facebook App ID</label>
                                <input type="text" x-model="config.facebook_client_id" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500 transition-colors">
                            </div>
                            <div>
                                <label class="block text-xs font-bold uppercase text-slate-500 mb-2">Facebook App Secret</label>
                                <input type="password" x-model="config.facebook_client_secret" placeholder="Secret..." class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500 transition-colors">
                            </div>
                        </div>
                    </div>

                    <!-- Email / SMTP -->
                    <div class="bg-slate-900 p-6 rounded-2xl border border-slate-800 space-y-4">
                        <h3 class="text-lg font-bold text-white border-b border-slate-800 pb-2 mb-4"><i class="fa-solid fa-envelope text-rose-500 mr-2"></i> Email & Branding</h3>
                        
                         <!-- Branding -->
                        <div class="grid grid-cols-1 gap-4 mb-4">
                             <div>
                                <label class="block text-xs font-bold uppercase text-slate-500 mb-2">Email Logo URL</label>
                                <input type="text" x-model="config.email_logo" placeholder="https://example.com/logo.png" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500">
                            </div>
                             <div>
                                <label class="block text-xs font-bold uppercase text-slate-500 mb-2">Email Signature (HTML/Text)</label>
                                <textarea x-model="config.email_signature" placeholder="Best regards,<br>TraKr Team" rows="2" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500"></textarea>
                            </div>
                        </div>

                        <!-- SMTP Config -->
                        <div class="grid grid-cols-2 gap-4 border-t border-slate-800 pt-4">
                            <div class="col-span-2">
                                <label class="block text-xs font-bold uppercase text-slate-500 mb-2">SMTP Host</label>
                                <input type="text" x-model="config.smtp_host" placeholder="smtp.gmail.com" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500">
                            </div>
                            <div>
                                <label class="block text-xs font-bold uppercase text-slate-500 mb-2">Port</label>
                                <input type="text" x-model="config.smtp_port" placeholder="587" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500">
                            </div>
                            <div>
                                <label class="block text-xs font-bold uppercase text-slate-500 mb-2">User</label>
                                <input type="text" x-model="config.smtp_user" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500">
                            </div>
                            <div class="col-span-2">
                                <label class="block text-xs font-bold uppercase text-slate-500 mb-2">Password</label>
                                <input type="password" x-model="config.smtp_pass" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500">
                            </div>
                        </div>
                    </div>

                    <!-- Push & Messaging -->
                    <div class="bg-slate-900 p-6 rounded-2xl border border-slate-800 space-y-4">
                        <h3 class="text-lg font-bold text-white border-b border-slate-800 pb-2 mb-4"><i class="fa-solid fa-bell text-emerald-500 mr-2"></i> Notifications</h3>
                        
                        <!-- OneSignal -->
                        <div class="space-y-2">
                            <p class="text-xs font-bold text-slate-400">OneSignal (App Notifications)</p>
                            <input type="text" x-model="config.onesignal_app_id" placeholder="App ID" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500">
                            <input type="password" x-model="config.onesignal_rest_key" placeholder="REST API Key" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500">
                        </div>

                        <!-- WhatsApp -->
                        <div class="space-y-2 pt-2 border-t border-slate-800">
                            <p class="text-xs font-bold text-slate-400">WhatsApp (AuthKey / API)</p>
                            <input type="text" x-model="config.whatsapp_api_url" placeholder="API Endpoint (https://...)" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500">
                            <input type="password" x-model="config.whatsapp_auth_key" placeholder="Auth Key" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500">
                        </div>
                    </div>

                     <!-- Premium Features Definition -->
                    <div class="bg-slate-900 p-6 rounded-2xl border border-slate-800 space-y-4">
                        <h3 class="text-lg font-bold text-white border-b border-slate-800 pb-2 mb-4"><i class="fa-solid fa-crown text-amber-500 mr-2"></i> Premium Features</h3>
                        <div>
                            <label class="block text-xs font-bold uppercase text-slate-500 mb-2">Plan Title</label>
                            <input type="text" x-model="config.premium_title" placeholder="TraKr Pro" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500">
                        </div>
                        <div>
                            <label class="block text-xs font-bold uppercase text-slate-500 mb-2">Features List (One per line)</label>
                            <textarea x-model="config.premium_features" placeholder="Unlimited Tasks&#10;Advanced AI Analysis&#10;Priority Support" rows="5" class="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500"></textarea>
                        </div>
                    </div>
                </div>
            </div>

            <!-- LOGS TAB -->
            <div x-show="tab === 'logs'" class="space-y-6">
                <h2 class="text-3xl font-bold">Security Audit</h2>
                <div class="bg-slate-900 rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
                    <table class="w-full text-left text-sm">
                        <thead class="bg-slate-800 text-xs font-bold uppercase text-slate-500"><tr><th class="p-4">Timestamp</th><th class="p-4">IP Address</th><th class="p-4">Event</th><th class="p-4">Details</th></tr></thead>
                        <tbody><template x-for="l in logs"><tr><td class="p-4 border-t border-slate-800 text-slate-500 whitespace-nowrap" x-text="l.created_at"></td><td class="p-4 border-t border-slate-800 font-mono text-xs text-indigo-400" x-text="l.ip"></td><td class="p-4 border-t border-slate-800 font-bold" x-text="l.event"></td><td class="p-4 border-t border-slate-800 text-slate-400" x-text="l.details"></td></tr></template></tbody>
                    </table>
                </div>
            </div>
        </main>
    </div>
    <script>
        function adminApp() {
            return {
                tab: 'users', users: [], logs: [], blocked: [], config: {}, newBlockIp: '',
                async init() {
                    this.refreshData();
                },
                async refreshData() {
                    const res = await fetch('admin.php?api=get_data').then(r => r.json());
                    if(res.status === 'success') {
                        this.users = res.data.users;
                        this.logs = res.data.logs;
                        this.blocked = res.data.blocked;
                        this.config = res.data.config;
                    }
                },
                async blockIp() {
                    if(!this.newBlockIp) return;
                    const res = await fetch('admin.php?api=block_ip', { method: 'POST', body: JSON.stringify({ip: this.newBlockIp}) }).then(r => r.json());
                    if(res.status === 'success') { this.newBlockIp = ''; this.refreshData(); }
                    else alert(res.error);
                },
                async unblockIp(ip) {
                    if(!confirm(`Are you sure you want to unblock ${ip}?`)) return;
                    const res = await fetch('admin.php?api=unblock_ip', { method: 'POST', body: JSON.stringify({ip}) }).then(r => r.json());
                    if(res.status === 'success') this.refreshData();
                },
                async saveConfig() {
                    const res = await fetch('admin.php?api=save_config', { method: 'POST', body: JSON.stringify(this.config) }).then(r => r.json());
                    if(res.status === 'success') alert('Configuration Updated Successfully');
                    else alert('Failed to save configuration');
                },
                logout() { fetch('api.php?action=logout').then(() => location.href = 'index.html'); }
            }
        }
    </script>
</body>
</html>