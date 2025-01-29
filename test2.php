<?php
// test.php - A simple PHP script to test GET and POST requests

// Output the request method
echo "Request Method: " . $_SERVER['REQUEST_METHOD'] . "<br>";

// Handle GET request
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    echo "GET Data: <br>";
    foreach ($_GET as $key => $value) {
        echo "$key: $value<br>";
    }
}

// Handle POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    echo "POST Data: <br>";
    foreach ($_POST as $key => $value) {
        echo "$key: $value<br>";
    }
}

// Output environment variables for debugging
echo "<br>Environment Variables:<br>";
echo "QUERY_STRING: " . $_SERVER['QUERY_STRING'] . "<br>";
echo "CONTENT_LENGTH: " . $_SERVER['CONTENT_LENGTH'] . "<br>";
echo "CONTENT_TYPE: " . $_SERVER['CONTENT_TYPE'] . "<br>";
?>