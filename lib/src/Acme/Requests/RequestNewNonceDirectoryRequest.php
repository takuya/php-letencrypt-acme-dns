<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpoint;

class RequestNewNonceDirectoryRequest extends AcmeDirectoryRequest {
  
  public function __construct(
    AcmeNonce     $nonce,
    ?AcmeAccount  $account = null,
    ?AcmeEndpoint $resource = null,
    string        $method = 'GET' ) {
    //
    parent::__construct( $nonce, $account, $resource, $method );
  }
  
  public function getBody(): string {
    return '';
  }
  
  public function getHeaders(): array {
    return [];
  }
}