<?php

include('OpenSSLHmacLayer.php');

$hmac = new HmacLayer(
  'qh3Wh0KLUqjLrLpiAaxlUvcgQyPSnuSxVQRASPNQQvw',
  '5201a261b60a759384ef59ec47fe98dff5a4d3457b21ea2d15b1e5c1355037a3'
);
$msg = $hmac->encrypt($argv[1]);
print $msg;
// $dec = $hmac->decrypt($msg);
// echo "\n" . $dec . "\n";