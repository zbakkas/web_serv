<?php
$query_string = getenv('QUERY_STRING');
parse_str($query_string, $params);

// Debugging output
echo "<pre>" . print_r($params, true) . "</pre>";

echo "Hello, " . $params['name'] . "!";
?>
