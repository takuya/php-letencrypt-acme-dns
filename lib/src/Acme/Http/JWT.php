<?php

namespace Takuya\LEClientDNS01\Acme\Http;

use Takuya\LEClientDNS01\Acme\Base64URLEncode;

class JWT {

  protected \OpenSSLAsymmetricKey  $private_key;
  public function __construct(string|\OpenSSLAsymmetricKey  $private_key_pem) {
    $this->private_key = is_string($private_key_pem)? openssl_pkey_get_private( $private_key_pem ):$private_key_pem;
  }
  private function convert():array {
    $ret = openssl_pkey_get_details( $this->private_key );
    $jwt = [
      // 順番は重要。配列の順番がとても重要
      'e'   => Base64URLEncode::encode( $ret['rsa']['e'] ),
      'kty' => 'RSA',// RSA 以外は面倒なのでサポートしない。
      'n'   => Base64URLEncode::encode( $ret['rsa']['n'] ),
    ];
    return $jwt;
  }
  public static function toJson(string $private_key_pem):string {
    return json_encode(self::toArray($private_key_pem));
  }
  public static  function toArray(string|\OpenSSLAsymmetricKey  $private_key_pem):array {
    $obj = new static($private_key_pem);
    return $obj->convert();
  }
}