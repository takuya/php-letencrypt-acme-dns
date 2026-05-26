<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\Base64URLEncode;
use Takuya\LEClientDNS01\Acme\AcmeAccount;

abstract  class AcmeRequest {
  protected AcmeNonce $nonce;
  protected ?AcmeAccount $account = null;
  protected string $method = 'POST';
  
  public static function encodeObject( array|object $data ): string {
    return Base64URLEncode::encode( json_encode( $data ) );
  }
  
  public static function payload( $array ): string {
    return static::encodeObject( $array );
  }
  
  public static function jwt( string $private_key_pem ) {
    $ret = openssl_pkey_get_details( openssl_pkey_get_private( $private_key_pem ) );
    $jwt = [
      // 順番は重要。配列の順番がとても重要
      'e'   => Base64URLEncode::encode( $ret['rsa']['e'] ),
      'kty' => 'RSA',// RSA 以外は面倒なのでサポートしない。
      'n'   => Base64URLEncode::encode( $ret['rsa']['n'] ),
    ];
    return $jwt;
  }
  
  public function getNonce(): AcmeNonce {
    return $this->nonce;
  }
  
  public static function signature( $protectedStr, $payloadStr, $private_key_pem ): string {
    $signingInput = $protectedStr.'.'.$payloadStr;
    $openSSL_asymmetric_key = openssl_pkey_get_private( $private_key_pem );
    openssl_sign( $signingInput, $signature, $openSSL_asymmetric_key, OPENSSL_ALGO_SHA256 );
    return Base64URLEncode::encode( $signature );
  }
  
  public function getHeaders(): array {
    return [
      'Content-Type' => 'application/jose+json',
      'Accept'       => 'application/jose+json',
    ];
  }
  public function getMethod(): string {
    return $this->method;
  }
  abstract public function getBody(): string;
  
  abstract public function getRequestUrl(): string;
}