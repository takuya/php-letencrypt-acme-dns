<?php

namespace Takuya\LEClientDNS01\Acme\Http;

class Rs256JwsSigner {
  public static function sign( string $protectedStr, string $payloadStr, string $private_key_pem ):string {
    return static::signature( $protectedStr, $payloadStr,$private_key_pem );
  }
  protected static function signature( string $protectedStr, string $payloadStr,  string $private_key_pem ): string {
    $signingInput = $protectedStr.'.'.$payloadStr;
    $openSSL_asymmetric_key = openssl_pkey_get_private( $private_key_pem );
    openssl_sign( $signingInput, $signature, $openSSL_asymmetric_key, OPENSSL_ALGO_SHA256 );
    return Base64URLEncode::encode( $signature );
  }
  public static function extractRsaPubJwk(string  $private_key_pem):array {
    $ret = openssl_pkey_get_details(openssl_pkey_get_private( $private_key_pem ) );
    $jwt = [
      // 順番は重要。
      //   ACMEで使うとき、この配列の順番がとても重要。
      //   自動整形で順番を変えないこと。
      'e'   => Base64URLEncode::encode( $ret['rsa']['e'] ),
      'kty' => 'RSA',// RSA 以外は面倒なのでサポートしない。
      'n'   => Base64URLEncode::encode( $ret['rsa']['n'] ),
    ];
    return $jwt;
  }
  public static function JwkString(string $private_key_pem):string {
    return json_encode(self::extractRsaPubJwk($private_key_pem));
  }
}