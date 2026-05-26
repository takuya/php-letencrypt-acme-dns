<?php

namespace Takuya\LEClientDNS01\Acme\Http;

use Takuya\LEClientDNS01\Acme\Base64URLEncode;

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
}