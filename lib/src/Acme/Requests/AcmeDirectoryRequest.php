<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpoint;

abstract class AcmeDirectoryRequest extends AcmeRequest {
  public function __construct(
    protected AcmeNonce     $nonce, // TODO::クラスにする
    protected ?AcmeAccount  $account = null,
    protected ?AcmeEndpoint $resource = null,
    protected string        $method = 'POST',
  ) {
  }
  
  // TODO : これ new Account の時だけだわ
  public static function protected( $jwt, $nonce, $url ): string {
    return static::encodeObject( [
      "alg"   => "RS256",
      "jwk"   => $jwt,
      "nonce" => $nonce, // 取得済みの Nonce
      "url"   => $url,   // Directoryから取得したURL
    ] );
  }
  
  protected function resource_url(): string {
    return $this->resource->getUrl();
  }
  
  public function getRequestUrl(): string {
    return $this->resource_url();
  }
  
  
}