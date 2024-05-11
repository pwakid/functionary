<?php

// 1. Array Filter by Keys
function array_filter_keys($array, $keys) {
    return array_intersect_key($array, array_flip((array) $keys));
}

// 2. Generate Random String
function generate_random_string($length = 10) {
    return substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
}

// 3. Sanitize Input
function sanitize_input($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// 4. Convert Snake Case to Camel Case
function snake_to_camel($string) {
    return lcfirst(str_replace(' ', '', ucwords(str_replace('_', ' ', $string))));
}

// 5. Pretty JSON Encode
function pretty_json_encode($data) {
    return json_encode($data, JSON_PRETTY_PRINT);
}

// 6. Check If Array is Associative
function is_assoc(array $arr) {
    return array_keys($arr) !== range(0, count($arr) - 1);
}

// 7. Redirect to URL
function redirect($url) {
    header("Location: $url");
    exit();
}

// 8. Convert Bytes to Human-Readable Format
function bytes_to_human($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    $factor = floor((strlen($bytes) - 1) / 3);
    return sprintf("%.2f", $bytes / pow(1024, $factor)) . @$units[$factor];
}

// 9. Validate Email Address
function validate_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// 10. Get File Extension
function get_file_extension($filename) {
    return pathinfo($filename, PATHINFO_EXTENSION);
}

// 11. Encrypt Data with OpenSSL
function encrypt_data($data, $key) {
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
    return base64_encode($encrypted . '::' . $iv);
}

// 12. Decrypt Data with OpenSSL
function decrypt_data($data, $key) {
    list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);
    return openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
}

// 13. Check SSL/TLS on Current Request
function is_https() {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443;
}

// 14. Human-Readable Time Difference
function human_time_diff($from, $to = '') {
    if (empty($to)) {
        $to = time();
    }
    $diff = (int) abs($to - $from);
    $units = [
        31536000 => 'year',
        2592000 => 'month',
        604800 => 'week',
        86400 => 'day',
        3600 => 'hour',
        60 => 'minute',
        1 => 'second'
    ];
    foreach ($units as $unit => $text) {
        if ($diff >= $unit) {
            $num = floor($diff / $unit);
            return $num.' '.$text.(($num > 1) ? 's' : '');
        }
    }
    return 'just now';
}

// 15. Simple Template Engine
function render_template($template, $data = []) {
    ob_start();
    extract($data);
    include $template;
    return ob_get_clean();
}

// 16. Slugify a String
function slugify($text) {
    $text = preg_replace('~[^\pL\d]+~u', '-', $text);
    $text = iconv('utf-8', 'us-ascii//TRANSLIT', $text);
    $text = preg_replace('~[^-\w]+~', '', $text);
    $text = trim($text, '-');
    $text = strtolower($text);
    return empty($text) ? 'n-a' : $text;
}

// 17. Check if String is JSON
function is_json($string) {
    json_decode($string);
    return (json_last_error() == JSON_ERROR_NONE);
}


// 18. Days Between Dates
function days_between_dates($date1, $date2) {
    $datetime1 = new DateTime($date1);
    $datetime2 = new DateTime($date2);
    $interval = $datetime1->diff($datetime2);
    return $interval->days;
}

// 19. Simple Cache Setter/Getter
function simple_cache($key, $data = null, $expire = 3600) {
    $file = 'cache/' . md5($key);
    if ($data !== null) {
        $content = serialize(['data' => $data, 'expires' => time() + $expire]);
        file_put_contents($file, $content);
        return true;
    }
    if (file_exists($file)) {
        $content = unserialize(file_get_contents($file));
        if ($content['expires'] > time()) {
            return $content['data'];
        }
        unlink($file);
    }
    return false;
}

// 20. Generate CSRF Token
function generate_csrf_token() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// 21. Verify CSRF Token
function verify_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && $_SESSION['csrf_token'] === $token;
}

// 22. Create Directory If Not Exists
function create_dir_if_not_exists($path) {
    if (!is_dir($path)) {
        mkdir($path, 0777, true);
    }
}

// 23. Get Client IP Address
function get_client_ip() {
    foreach (['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $key) {
        if (array_key_exists($key, $_SERVER) === true) {
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                    return $ip;
                }
            }
        }
    }
    return 'UNKNOWN';
}

// 24. Convert CSV to Array
function csv_to_array($filename, $delimiter = ',') {
    if (!file_exists($filename) || !is_readable($filename)) {
        return FALSE;
    }
    $header = NULL;
    $data = array();
    if (($handle = fopen($filename, 'r')) !== FALSE) {
        while (($row = fgetcsv($handle, 1000, $delimiter)) !== FALSE) {
            if (!$header) {
                $header = $row;
            } else {
                $data[] = array_combine($header, $row);
            }
        }
        fclose($handle);
    }
    return $data;
}

// 25. Format Date in Relative Terms
function relative_date($time) {
    $time = strtotime($time);
    $diff = time() - $time;
    if ($diff < 60) {
        return 'just now';
    } elseif ($diff < 3600) {
        return floor($diff / 60) . ' minutes ago';
    } elseif ($diff < 86400) {
        return floor($diff / 3600) . ' hours ago';
    } else {
        return date('Y-m-d', $time);
    }
}

// 26. Send HTML Email
function send_html_email($to, $subject, $htmlContent, $from = null) {
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    if ($from) {
        $headers .= 'From: ' . $from . "\r\n";
    }
    return mail($to, $subject, $htmlContent, $headers);
}

// 27. Get Gravatar URL
function get_gravatar($email, $size = 80) {
    $hash = md5(strtolower(trim($email)));
    return "https://www.gravatar.com/avatar/$hash?s=$size";
}

// 28. Simple Logging Function
function simple_log($message, $file = 'log.txt') {
    file_put_contents($file, date('Y-m-d H:i:s') . " - " . $message . "\n", FILE_APPEND);
}

// 29. Check if Request is AJAX
function is_ajax_request() {
    return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}
// 30. Compress HTML Output
function compress_html($buffer) {
    $search = array(
        '/\>[^\S ]+/s',   // strip whitespaces after tags, except space
        '/[^\S ]+\</s',   // strip whitespaces before tags, except space
        '/(\s)+/s',       // shorten multiple whitespace sequences
        '/<!--(.|\s)*?-->/' // Remove HTML comments
    );
    $replace = array(
        '>',
        '<',
        '\\1',
        ''
    );
    return preg_replace($search, $replace, $buffer);
}

// 31. Array to CSV Conversion
function array_to_csv(array $array, $download = "") {
    if ($download) {
        header('Content-Type: application/csv');
        header('Content-Disposition: attachment; filename="' . $download . '"');
    }
    ob_start();
    $f = fopen('php://output', 'w') or die("Can't open php://output");
    foreach ($array as $line) {
        fputcsv($f, $line);
    }
    fclose($f) or die("Can't close php://output");
    $str = ob_get_contents();
    ob_end_clean();
    return $str;
}

// 32. Detect Mobile Device
function is_mobile_device() {
    $aMobileUA = [
        '/iphone/i', '/ipod/i', '/ipad/i', '/android/i', '/blackberry/i',
        '/webos/i'
    ];
    foreach ($aMobileUA as $sMobileKey => $sMobileOS) {
        if (preg_match($sMobileOS, $_SERVER['HTTP_USER_AGENT'])) {
            return true;
        }
    }
    return false;
}

// 33. Minify JavaScript
function minify_js($buffer) {
    return preg_replace(array('/\s+\n/', '/\n\s+/', '/ +/'), array("\n", "\n ", ' '), $buffer);
}

// 34. Get Current URL
function get_current_url() {
    $http = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http");
    return $http . "://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
}

// 35. File Size Formatted
function format_file_size($size) {
    $units = array(' B', ' KB', ' MB', ' GB', ' TB');
    for ($i = 0; $size >= 1024 && $i < 4; $i++) $size /= 1024;
    return round($size, 2) . $units[$i];
}

// 36. Simple Data Encryption
function simple_encrypt($text, $salt = 'simple_salt') {
    return trim(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $salt, $text, MCRYPT_MODE_ECB)));
}

// 37. Simple Data Decryption
function simple_decrypt($text, $salt = 'simple_salt') {
    return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $salt, base64_decode($text), MCRYPT_MODE_ECB));
}

// 38. Generate SEO URL
function generate_seo_url($string) {
    $string = strtolower($string);
    $string = preg_replace("/[^a-z0-9_\s-]/", "", $string);
    $string = preg_replace("/[\s-]+/", " ", $string);
    $string = preg_replace("/[\s_]/", "-", $string);
    return $string;
}

// 39. Validate and Sanitize URL
function validate_and_sanitize_url($url) {
    if (filter_var($url, FILTER_VALIDATE_URL)) {
        return filter_var($url, FILTER_SANITIZE_URL);
    }
    return false;
}

// 40. Secure Session Start
function secure_session_start() {
    $session_name = 'secure_session';
    $secure = true;
    $httponly = true;
    ini_set('session.use_only_cookies', 1);
    $cookieParams = session_get_cookie_params();
    session_set_cookie_params($cookieParams["lifetime"], $cookieParams["path"], $cookieParams["domain"], $secure, $httponly);
    session_name($session_name);
    session_start();
    session_regenerate_id(true);
}
