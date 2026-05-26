<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;

class RequestNewNonceDirectoryRequest extends AcmeDirectoryRequest {
  
  public function __construct(
    protected AcmeNonce $nonce,
    protected string    $endpoint_url,
    protected string    $method = "GET"
  ) {
  }
  
  public function getBody(): string {
    return '';
  }
  
  public function getHeaders(): array {
    return [];
  }
  public function getRequestUrl(): string {
    return $this->endpoint_url;
  }
}