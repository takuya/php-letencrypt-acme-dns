<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\Base64URLEncode;
use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;

abstract class AcmeRequest {
  protected string $method = 'POST';
  
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