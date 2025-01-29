<?php
header("Content-Type: text/html");

echo "<h1>PHP CGI Script</h1>";

$method = getenv("REQUEST_METHOD");
echo "<p>Request Method: " . htmlspecialchars($method) . "</p>";

if ($method == "GET") {
    parse_str(getenv("QUERY_STRING"), $_GET);
    echo "<p>Name: " . htmlspecialchars($_GET["name"] ?? "No Name") . "</p>";
} elseif ($method == "POST") {
    parse_str(file_get_contents("php://input"), $_POST);
    echo "<p>Name: " . htmlspecialchars($_POST["name"] ?? "No Name") . "</p>";
}
?>