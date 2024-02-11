$var1 = "Hello, World!";

// Send $var1 to php://input
$stream = fopen("php://input", "w");
fwrite($stream, $var1);
fclose($stream);

// Read the contents from php://input
$contents = file_get_contents("php://input");

echo $contents;
