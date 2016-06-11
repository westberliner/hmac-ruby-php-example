<?php

class HmacLayer
{
  public $sharedSecret;
  public $clientSecret;
  public static $encryptionMethod = "aes-256-cbc";
  public static $hmacMethod = "sha256";
  public static $macSize = 64;
  public $ivSize;
  private $hmacKey;
  private $iv;

  public function __construct($shared_secret, $client_secret)
  {
    $this->sharedSecret = $shared_secret;
    $this->clientSecret = $client_secret;
    $this->hmacKey = hash(self::$hmacMethod, $this->clientSecret . $this->sharedSecret);
    $this->encryptionKey = $this->hmacKey;
    $this->ivSize = openssl_cipher_iv_length(self::$encryptionMethod);
    $this->initVector = mcrypt_create_iv($this->ivSize, MCRYPT_RAND);
  }

  public function encrypt($msg)
  {
    $enc = $this->encryptMsg($msg);
    $encIvMsg = $this->initVector . $enc;

    $hmac = $this->generateHmac($encIvMsg);

    return rawurlencode(base64_encode($hmac));

  }

  public function decrypt($msg)
  {
    $msg = base64_decode(rawurldecode($msg));

    $hmac = substr($msg, 0, self::$macSize);
    $msg = substr($msg, self::$macSize);

    $compareHmac = $this->generateHmac($msg, false);
    
    if ($hmac !== $compareHmac) {
        return false;
    }
    
    $iv = substr($msg, 0, $this->ivSize);
    $msg = substr($msg, $this->ivSize);

    if($dec = $this->decryptMsg($iv, $msg)) {
      return $dec;
    } else {
      return $this->decryptMsg($iv, $msg, false);
    } 
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
    return openssl_encrypt(
      $msg, 
      self::$encryptionMethod, 
      $this->encryptionKey,
      false,
      $this->initVector
    );
  }

  private function decryptMsg($iv, $msg, $encode = true)
  {
    if($encode) {
      $msg =  base64_encode($msg);
    }
    
    return openssl_decrypt(
      $msg, 
      self::$encryptionMethod, 
      $this->encryptionKey,
      false,
      $iv
    );
  }

  private function pkcs5Pad($text, $blocksize)
  {
      $pad = $blocksize - (strlen($text) % $blocksize);
      return $text . str_repeat(chr($pad), $pad);
  }
}
