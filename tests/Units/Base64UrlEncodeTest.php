<?php

namespace tests\Units;

use tests\TestCase;
use function Takuya\Utils\base64_url_encode;
use function Takuya\Utils\base64_url_decode;
use Takuya\LEClientDNS01\Acme\Http\Base64URLEncode;

class Base64UrlEncodeTest extends TestCase {
  
  public function test_encode_base64_url_safe(){
    foreach ( [32, 128, 1024, 4096] as $length ) {
      $rand = openssl_random_pseudo_bytes($length);
      $enc_str = base64_url_encode($rand);
      $dec_str = base64_url_decode($enc_str);
      $this->assertEquals($rand,$dec_str);
    }
  }
  public function test_encode_decode_base64_url_safe_class() {
    foreach ( [32,33,34,35,36,128, 1024, 4096] as $length ) {
      $rand = openssl_random_pseudo_bytes($length);
      // enc
      $enc_str = Base64URLEncode::encode($rand);
      $dec_str = base64_url_decode($enc_str);
      $this->assertEquals($rand,$dec_str);
      //// dec
      $enc_str = base64_url_encode($rand);
      $dec_str = Base64URLEncode::decode($enc_str);
      $this->assertEquals($rand,$dec_str);
      // enc dec
      $enc_str = Base64URLEncode::encode($rand);
      $dec_str = Base64URLEncode::decode($enc_str);
      $this->assertEquals($rand,$dec_str);
    }
  
  }
  
}