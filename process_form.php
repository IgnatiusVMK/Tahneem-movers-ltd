<?php

use Dotenv\Dotenv;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '/vendor/autoload.php';

session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Load .env
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

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

// Ensure the request method is POST
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    die('Invalid request method.');
}

// Get User IP
$user_ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';

// Check if the user is already blocked
$stmt = $pdo->prepare("SELECT blocked_until FROM blocked_users WHERE ip_address = ? LIMIT 1");
$stmt->execute([$user_ip]);
$block = $stmt->fetch();

if ($block && strtotime($block['blocked_until']) > time()) {
    session_start();
    $_SESSION['error_message'] = "Too many requests. You are blocked until " . htmlspecialchars($block['blocked_until']);
    header("Location: index.php#estimate-form", true, 302);
    exit;
}

// Clean old email request records older than 1 hour
$pdo->exec(statement: "DELETE FROM email_requests WHERE timestamp < NOW() - INTERVAL 1 HOUR");

// Log this request into the database
$stmt = $pdo->prepare("INSERT INTO email_requests (ip_address, timestamp) VALUES (?, NOW())");
$stmt->execute([$user_ip]);

// Check if the IP has sent more than 2 emails in the last 15 minutes
$stmt = $pdo->prepare("SELECT COUNT(*) FROM email_requests WHERE ip_address = ? AND timestamp > NOW() - INTERVAL 15 MINUTE");
$stmt->execute([$user_ip]);
$email_count = $stmt->fetchColumn();

if ($email_count > 2) {
    $blocked_until = date("Y-m-d H:i:s", strtotime("+2 weeks"));
    $stmt = $pdo->prepare("INSERT INTO blocked_users (ip_address, blocked_until) VALUES (?, ?) 
                           ON DUPLICATE KEY UPDATE blocked_until = VALUES(blocked_until)");
    $stmt->execute([$user_ip, $blocked_until]);

    // Store error message in session and redirect
    session_start();
    $_SESSION['error_message'] = "Too many requests. You are blocked until " . htmlspecialchars($blocked_until);
    header("Location: index.php#estimate-form", true, 302);
    exit;
}

// Validate inputs
$name = htmlspecialchars(trim(filter_input(INPUT_POST, 'name', FILTER_SANITIZE_FULL_SPECIAL_CHARS)));
$email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
$size_house_from = htmlspecialchars(trim($_POST['size_house_from'] ?? ''));
$from_to_where = htmlspecialchars(trim($_POST['from_to_where'] ?? ''));
$floor_to_floor = htmlspecialchars(trim($_POST['floor_to_floor'] ?? ''));
$moving_schedule = htmlspecialchars(trim($_POST['moving_schedule'] ?? ''));
$message = htmlspecialchars(trim($_POST['message'] ?? ''));

if (!$email) {
    die("Invalid email format.");
}

// Initialize PHPMailer
$mail = new PHPMailer(true);

try {
    // SMTP Configuration
    $mail->isSMTP();
    $mail->Host = $_ENV['SMTP_HOST'];
    $mail->SMTPAuth = true;
    $mail->Username = $_ENV['SMTP_USER'];
    $mail->Password = $_ENV['SMTP_PASS'];
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port = $_ENV['SMTP_PORT'];

    // Email Content
    $mail->setFrom($_ENV['SMTP_USER'], 'Quotation Inquiry');
    $mail->addAddress('ignatiusvmk@gmail.com');
    $mail->isHTML(true);
    $mail->Subject = 'Services Estimate Request';

    // Email Body
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

    // Send Email
    if ($mail->send()) {
        header("Location: index.php#estimate-form", true, 302);
        exit;
    } else {
        throw new Exception("Email sending failed.");
    }
} catch (Exception $e) {
    error_log("Email error: " . $mail->ErrorInfo);
    die("Message could not be sent. Please try again later.");
}
?>
