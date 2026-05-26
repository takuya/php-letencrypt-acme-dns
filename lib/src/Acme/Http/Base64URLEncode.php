<?php

namespace Takuya\LEClientDNS01\Acme\Http;

class Base64URLEncode {
  public static function encode(string $string): string {
    return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
  }
  
  public static function decode(string $str): string  {
    if( $len = strlen($str) % 4 > 0){
      $str = str_pad($str,$len+($len%4>0?4-$len%4:0),'=');
    }
    return base64_decode(strtr($str, '-_', '+/'));
  }
}
