<?php

namespace tests\Units;

use tests\TestCase;
use function Takuya\Utils\base64_url_encode;
use function Takuya\Utils\base64_url_decode;

class Base64UrlEncodeTest extends TestCase {
  
  public function test_encode_base64_url_safe(){
    foreach ( [32, 128, 1024, 4096] as $length ) {
      $rand = openssl_random_pseudo_bytes($length);
      $enc_str = base64_url_encode($rand);
      $dec_str = base64_url_decode($enc_str);
      $this->assertEquals($rand,$dec_str);
    }
  }
  
}