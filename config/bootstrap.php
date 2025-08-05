<?php

require_once __DIR__ . '/../vendor/autoload.php';

// Determine environment (default to test if not set)
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

// Load environment variables
try {
    $envFile = ".env.$environment";
    $dotenvDirectory = __DIR__ . '/..';

    if (!file_exists($dotenvDirectory . '/' . $envFile)) {
        throw new RuntimeException("Environment file $envFile not found");
    }

    $dotenv = Dotenv\Dotenv::createImmutable($dotenvDirectory, $envFile);
    $dotenv->load();
    
    // Validate required variables
    $dotenv->required([
        'DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS',
        'RECAPTCHA_SITE', 'RECAPTCHA_SECRET'
    ]);
    
} catch (Exception $e) {
    if ($environment === 'test') {
        die("Configuration Error: " . $e->getMessage());
    } else {
        error_log("Configuration Error: " . $e->getMessage());
        die("System configuration error. Please contact support.");
    }
}

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Display error messages if they exist in session
if (isset($_SESSION['error_message'])) {
    echo "<script>
        document.addEventListener('DOMContentLoaded', function() {
            var errorDiv = document.createElement('div');
            errorDiv.style.color = 'red';
            errorDiv.style.padding = '10px';
            errorDiv.style.margin = '10px 0';
            errorDiv.style.border = '1px solid red';
            errorDiv.style.background = '#ffdddd';
            errorDiv.textContent = '" . addslashes($_SESSION['error_message']) . "';
            
            var form = document.querySelector('#estimate-form');
            if (form) {
                form.insertAdjacentElement('beforebegin', errorDiv);
            }
        });
    </script>";
    unset($_SESSION['error_message']);
}