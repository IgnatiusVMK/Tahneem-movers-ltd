<?php
// First determine environment before loading anything else
$environment = getenv('APP_ENV') ?: 'test';

// Set error reporting based on environment
if ($environment === 'test') {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
}

ob_start(); // Start output buffering
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

use Dotenv\Dotenv;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '/vendor/autoload.php';

// Load Environment Variables with safety checks
try {
    $envFile = ".env.$environment";
    
    // Verify environment file exists
    if (!file_exists(__DIR__ . '/' . $envFile)) {
        throw new RuntimeException("Environment file $envFile not found");
    }

    $dotenv = Dotenv::createImmutable(__DIR__, $envFile);
    $dotenv->load();
    
    // Validate required variables
    $dotenv->required([
        'DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS',
        'RECAPTCHA_SITE', 'RECAPTCHA_SECRET'
    ]);
    
    // Environment-specific validations
    if ($environment === 'prod') {
        $dotenv->required('SMTP_HOST')->notEmpty();
    }
    
} catch (Exception $e) {
    // Handle errors appropriately per environment
    if ($environment === 'test') {
        die("Environment Error: " . $e->getMessage());
    } else {
        error_log("Environment Error: " . $e->getMessage());
        die("System configuration error. Please contact support.");
    }
}

// Database Connection
try {
    $pdo = new PDO(
        "mysql:host={$_ENV['DB_HOST']};port={$_ENV['DB_PORT']};dbname={$_ENV['DB_NAME']}",
        $_ENV['DB_USER'],
        $_ENV['DB_PASS'],
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_PERSISTENT => true
        ]
    );
} catch (PDOException $e) {
    error_log("Database connection error: " . $e->getMessage());
    die("Database error. Please try again later.");
}

// Ensure Request Method is POST
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    die('Invalid request method.');
}

// Honeypot check
if (!empty($_POST['website'])) {
    die("Spam detected (honeypot).");
}

// Verify Google reCAPTCHA
$recaptcha_response = $_POST['g-recaptcha-response'] ?? '';
// Get User IP
$user_ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';

$recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify';
$recaptcha_secret = $_ENV['RECAPTCHA_SECRET'];

$verify_response = file_get_contents($recaptcha_url . '?secret=' . urlencode($recaptcha_secret) . '&response=' . urlencode($recaptcha_response) . '&remoteip=' . urlencode($user_ip));
$response_data = json_decode($verify_response);

if (!$response_data->success) {
    $_SESSION['error_message'] = "reCAPTCHA verification failed. Please try again.";
    header("Location: " . getRefererPage(), true, 302);
    exit;
}

// JavaScript-enabled check
if (empty($_POST['js_enabled']) || $_POST['js_enabled'] !== 'yes') {
    die("Spam detected (no JS).");
}

// Time-based submission check (form filled too fast)
$form_token_time = intval($_POST['form_token'] ?? 0);
if (time() - $form_token_time < 3) { // less than 3 seconds is suspicious
    die("Spam detected (submitted too quickly).");
}

// Check if the user is already blocked
$stmt = $pdo->prepare("SELECT blocked_until FROM blocked_users WHERE ip_address = ? LIMIT 1");
$stmt->execute([$user_ip]);
$block = $stmt->fetch();

if ($block && strtotime($block['blocked_until']) > time()) {
    $_SESSION['error_message'] = "Too many requests. You are blocked until " . htmlspecialchars($block['blocked_until']);
    header("Location: " . getRefererPage(), true, 302);
    exit;
}

// Clean Old Records
$pdo->exec("DELETE FROM email_requests WHERE timestamp < NOW() - INTERVAL 1 HOUR");

// Log Request
$stmt = $pdo->prepare("INSERT INTO email_requests (ip_address, timestamp) VALUES (?, NOW())");
$stmt->execute([$user_ip]);

// Check Request Limit
$stmt = $pdo->prepare("SELECT COUNT(*) FROM email_requests WHERE ip_address = ? AND timestamp > NOW() - INTERVAL 15 MINUTE");
$stmt->execute([$user_ip]);
$email_count = $stmt->fetchColumn();

if ($email_count > 2) {
    $blocked_until = date("Y-m-d H:i:s", strtotime("+2 weeks"));
    $stmt = $pdo->prepare("INSERT INTO blocked_users (ip_address, blocked_until) VALUES (?, ?) 
                           ON DUPLICATE KEY UPDATE blocked_until = VALUES(blocked_until)");
    $stmt->execute([$user_ip, $blocked_until]);

    $_SESSION['error_message'] = "Too many requests. You are blocked until " . htmlspecialchars($blocked_until);
    header("Location: " . getRefererPage(), true, 302);
    exit;
}

// Validate Inputs
$name = htmlspecialchars(trim(filter_input(INPUT_POST, 'name', FILTER_SANITIZE_FULL_SPECIAL_CHARS)));
$email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
$phone = htmlspecialchars(trim($_POST['phone'] ?? ''));
$size_house_from = htmlspecialchars(trim($_POST['size_house_from'] ?? ''));
$from_to_where = htmlspecialchars(trim($_POST['from_to_where'] ?? ''));
$floor_to_floor = htmlspecialchars(trim($_POST['floor_to_floor'] ?? ''));
$moving_schedule = htmlspecialchars(trim($_POST['moving_schedule'] ?? ''));
$message = htmlspecialchars(trim($_POST['message'] ?? ''));

// Phone number validation for Kenyan format (+254XXXXXXXXX)
if (!preg_match('/^\+254[0-9]{9}$/', $phone)) {
    $_SESSION['error_message'] = "Please enter a valid Kenyan phone number starting with +254 followed by 9 digits";
    header("Location: " . getRefererPage(), true, 302);
    exit;
}

if (!$email) {
    die("Invalid email format.");
}

// Send Email with PHPMailer
$mail = new PHPMailer(true);

$mail->SMTPDebug = 2; // Enable verbose debug output
$mail->Debugoutput = function($str, $level) {
    error_log("PHPMailer: $str");
};

try {

    $mail = new PHPMailer(true);
    
    // Debugging setup
    $mail->SMTPDebug = 2;
    $mail->Debugoutput = function($str, $level) {
        error_log("PHPMailer: $str");
    };

    // Log SMTP settings
    error_log("Attempting to send email with settings:");
    error_log("Host: ".$_ENV['SMTP_HOST']);
    error_log("User: ".$_ENV['SMTP_USER']);
    error_log("Port: ".$_ENV['SMTP_PORT']);

    $mail->isSMTP();
    $mail->Host = $_ENV['SMTP_HOST'];
    $mail->SMTPAuth = true;
    $mail->Username = $_ENV['SMTP_USER'];
    $mail->Password = $_ENV['SMTP_PASS'];
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port = $_ENV['SMTP_PORT'];

    $mail->setFrom($_ENV['SMTP_USER'], 'Quotation Inquiry');
    $mail->addAddress('ignatiusvmk@gmail.com');
    /* $mail->addAddress('info.tahneemlogisticsltd@gmail.com'); */

    $mail->addCC('ivmkariuki@gmail.com');
    // $mail->addCC('sales@tahneemmovers.com');

    $mail->isHTML(true);
    $mail->Subject = 'Services Estimate Request';

    $mail->Body = "<html><head><style>
        body { font-family: Arial, sans-serif; background-color: #f8f9fa; }
        .email-container { max-width: 600px; background: #ffffff; padding: 20px; border: 1px solid #ddd; }
        h3 { background: #0c5f10; color: #ffffff; padding: 10px; text-align: center; }
        table { width: 100%; border-collapse: collapse; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        strong { color: #343a40; }
        .footer { text-align: center; font-size: 12px; color: #666; padding-top: 10px; }
    </style></head><body>
        <div class='email-container'>
            <h3>Quotation Request from Web-Visitors</h3>
            <table>
                <tr><td><strong>Name:</strong></td><td>$name</td></tr>
                <tr><td><strong>Email:</strong></td><td>$email</td></tr>
                <tr><td><strong>Phone:</strong></td><td>$phone</td></tr>
                <tr><td><strong>IP Address:</strong></td><td>$user_ip</td></tr>
                <tr><td><strong>Size of House:</strong></td><td>$size_house_from</td></tr>
                <tr><td><strong>Moving From → To:</strong></td><td>$from_to_where</td></tr>
                <tr><td><strong>Floor (From → To):</strong></td><td>$floor_to_floor</td></tr>
                <tr><td><strong>Move Date:</strong></td><td>$moving_schedule</td></tr>
                <tr><td><strong>Message:</strong></td><td>$message</td></tr>
            </table>
            <div class='footer'>This email was automatically generated. Please do not reply.</div>
        </div>
    </body></html>";

    if ($mail->send()) {
        error_log("Email successfully sent");
        header("Location: " . getRefererPage(), true, 302);
        exit;
    } else {
        throw new Exception("Email sending failed.");
    }
} catch (Exception $e) {
    error_log("Email error: " . $e->getMessage());
    error_log("PHPMailer ErrorInfo: " . $mail->ErrorInfo);
    die("Message could not be sent. Please try again later. Error logged.");
}

ob_end_flush(); // Send output buffer

// Function to get the referring page with fragment
function getRefererPage() {
    $referer = $_SERVER['HTTP_REFERER'] ?? 'index.php';
    $url_parts = parse_url($referer);
    $path = $url_parts['path'] ?? 'index.php';
    $fragment = isset($_POST['form_anchor']) ? '#' . $_POST['form_anchor'] : '#estimate-form';
    
    // Ensure we don't redirect to external sites
    $allowed_domains = [$_SERVER['HTTP_HOST'], 'www.tahneemmovers.com']; // Add your domains
    $referer_domain = parse_url($referer, PHP_URL_HOST);
    
    if (!in_array($referer_domain, $allowed_domains)) {
        return 'index.php' . $fragment;
    }
    
    return $path . $fragment;
}
?>