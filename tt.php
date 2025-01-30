#!/usr/bin/php
<?php
header("Content-Type: text/html");

echo "<html><body><h1>PHP POST Test</h1>";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    echo "<p>Received POST data:</p>";
    echo "<pre>";
    echo file_get_contents("php://input");  // Read raw POST data
    echo "</pre>";
} else {
    echo "<p>Send a POST request to see data here.</p>";
}

echo "</body></html>";
?>
