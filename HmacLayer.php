<?php

class HmacLayer
{
  public $sharedSecret;
  public $clientSecret;
  public static $encryptionMethod = MCRYPT_RIJNDAEL_128;
  public static $encryptionMode = MCRYPT_MODE_CBC;
  public static $encryptionKeyLength = 32;
  public static $hmacMethod = "sha256";
  public static $macSize = 64;
  public static $ivSize = 16;
  private $hmacKey;
  private $iv;

  public function __construct($shared_secret, $client_secret)
  {
    $this->sharedSecret = $shared_secret;
    $this->clientSecret = $client_secret;
    $this->hmacKey = hash(self::$hmacMethod, $this->clientSecret . $this->sharedSecret);
    $this->encryptionKey = substr($this->hmacKey, 0, self::$encryptionKeyLength);
    $this->initVector = openssl_random_pseudo_bytes(self::$ivSize);
  }

  public function encrypt($msg)
  {
    $enc = $this->encryptMsg($msg);
    $encIvMsg = $this->initVector . $enc;

    $hmac = $this->generateHmac($encIvMsg);

    return base64_encode(rawurlencode($hmac));

  }

  public function decrypt($msg)
  {
    $msg = rawurldecode(base64_decode($msg));

    $hmac = substr($msg, 0, self::$macSize);
    $msg = substr($msg, self::$macSize);

    $compareHmac = $this->generateHmac($msg, false);

    if ($hmac !== $compareHmac) {
        return false;
    }

    $iv = substr($msg, 0, self::$ivSize);
    $msg = substr($msg, self::$ivSize);

    return $this->decryptMsg($msg);
  }

  private function generateHmac($msg, $appendMsg = true)
  {
    $hmacMsg = hash_hmac(self::$hmacMethod, $msg, $this->hmacKey);

    if($appendMsg) {
      return $hmacMsg . $msg;
    }
    return $hmacMsg;
  }

  private function encryptMsg($msg)
  {
    return  mcrypt_encrypt(
      self::$encryptionMethod,
      $this->encryptionKey,
      $msg,
      self::$encryptionMode,
      $this->initVector
    );
  }

  private function decryptMsg($msg)
  {
    return mcrypt_decrypt(
      self::$encryptionMethod,
      $this->encryptionKey,
      $msg,
      self::$encryptionMode,
      $this->initVector
    );
  }

  private function pkcs5Pad($text, $blocksize)
  {
      $pad = $blocksize - (strlen($text) % $blocksize);
      return $text . str_repeat(chr($pad), $pad);
  }
}
