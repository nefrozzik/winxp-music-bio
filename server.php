<?php
// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Заголовки для правильной работы
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

$action = isset($_GET['action']) ? $_GET['action'] : '';
$dataFile = 'data.json';
$defaultFile = 'default_data.json';
$authFile = 'auth.json';

// Ensure default_data.json exists if data.json exists
if (file_exists($dataFile) && !file_exists($defaultFile)) {
    copy($dataFile, $defaultFile);
}

function requireAuth($input) {
    global $authFile;
    if (file_exists($authFile)) {
        $auth = json_decode(file_get_contents($authFile), true);
        if (isset($input['login']) && isset($input['hash']) && 
            $auth['login'] === $input['login'] && $auth['hash'] === $input['hash']) {
            return true;
        }
    }
    http_response_code(403);
    echo json_encode(["success" => false, "error" => "Доступ запрещен"]);
    exit;
}

// 1. Отдача данных для сайта
if ($action === 'getData') {
    if (file_exists($dataFile)) {
        echo file_get_contents($dataFile);
    } else {
        echo json_encode(["error" => "empty"]);
    }
    exit;
}

// 2. Проверка: установлен ли уже пароль?
if ($action === 'checkAuth') {
    echo json_encode(["isSetup" => file_exists($authFile)]);
    exit;
}

// 3. Поиск информации и платформ по UPC
if ($action === 'lookupUpc') {
    $upc = isset($_GET['upc']) ? preg_replace('/[^0-9]/', '', $_GET['upc']) : '';
    if (!$upc) {
        echo json_encode(["error" => "empty_upc"]);
        exit;
    }
    $itunesUrl = "https://itunes.apple.com/lookup?upc=" . urlencode($upc);
    $itunesRaw = @file_get_contents($itunesUrl);
    $deezerUrl = "https://api.deezer.com/album/upc:" . urlencode($upc);
    $deezerRaw = @file_get_contents($deezerUrl);
    
    echo json_encode([
        "upc" => $upc,
        "itunes" => $itunesRaw ? json_decode($itunesRaw, true) : null,
        "deezer" => $deezerRaw ? json_decode($deezerRaw, true) : null
    ]);
    exit;
}

// Получаем данные от браузера
$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) $input = [];

// 3. Создание первого пароля
if ($action === 'setupAuth') {
    if (!file_exists($authFile)) {
        $login = isset($input['login']) ? $input['login'] : '';
        $hash = isset($input['hash']) ? $input['hash'] : '';
        
        if (!is_string($login) || trim($login) === '') {
            echo json_encode(["success" => false, "error" => "Неверный логин"]);
            exit;
        }
        if (!is_string($hash) || !preg_match('/^[a-f0-9]{64}$/i', $hash)) {
            echo json_encode(["success" => false, "error" => "Неверный формат хеша"]);
            exit;
        }
        
        file_put_contents($authFile, json_encode([
            "login" => $login,
            "hash" => $hash
        ]));
        echo json_encode(["success" => true]);
    } else {
        echo json_encode(["success" => false, "error" => "Уже настроено"]);
    }
    exit;
}

// 4. Проверка логина и пароля при входе в админку
if ($action === 'login') {
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    $rateLimitFile = sys_get_temp_dir() . '/login_rate_' . md5($ip) . '.json';
    
    $attempts = [];
    $now = time();
    
    if (file_exists($rateLimitFile)) {
        $data = json_decode(file_get_contents($rateLimitFile), true);
        if (is_array($data)) {
            $attempts = $data;
        }
    }
    
    $attempts = array_filter($attempts, function($timestamp) use ($now) {
        return ($now - $timestamp) < 60;
    });
    
    if (count($attempts) >= 10) {
        http_response_code(429);
        echo json_encode(["success" => false, "error" => "Too many requests"]);
        exit;
    }
    
    $attempts[] = $now;
    file_put_contents($rateLimitFile, json_encode(array_values($attempts)));
    
    if (file_exists($authFile)) {
        $auth = json_decode(file_get_contents($authFile), true);
        if (isset($input['login']) && isset($input['hash']) && 
            $auth['login'] === $input['login'] && $auth['hash'] === $input['hash']) {
            echo json_encode(["success" => true]);
        } else {
            echo json_encode(["success" => false]);
        }
    } else {
        echo json_encode(["success" => false]);
    }
    exit;
}

// 5. Сохранение настроек сайта
if ($action === 'saveData') {
    requireAuth($input);
    
    if (!isset($input['data']) || (!is_array($input['data']) && !is_object($input['data']))) {
        echo json_encode(["success" => false, "error" => "Неверный формат данных"]);
        exit;
    }
    
    file_put_contents($dataFile, json_encode($input['data'], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    echo json_encode(["success" => true]);
    exit;
}

// 6. Сохранение данных как default_data
if ($action === 'saveDefault') {
    requireAuth($input);
    
    if (!isset($input['data']) || (!is_array($input['data']) && !is_object($input['data']))) {
        echo json_encode(["success" => false, "error" => "Неверный формат данных"]);
        exit;
    }
    
    file_put_contents($defaultFile, json_encode($input['data'], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    echo json_encode(["success" => true]);
    exit;
}

// 7. Сброс к дефолтным данным
if ($action === 'reset') {
    requireAuth($input);
    
    if (file_exists($defaultFile)) {
        copy($defaultFile, $dataFile);
        echo json_encode(["success" => true]);
    } else {
        echo json_encode(["success" => false, "error" => "Нет дефолтных данных"]);
    }
    exit;
}
?>