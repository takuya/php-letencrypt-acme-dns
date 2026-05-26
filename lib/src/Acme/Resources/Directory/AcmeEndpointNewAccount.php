<?php

namespace Takuya\LEClientDNS01\Acme\Resources\Directory;

use Takuya\LEClientDNS01\Acme\Requests\AcmeDirectoryRequest;
use Takuya\LEClientDNS01\Acme\Requests\AcmeNonce;
use Takuya\LEClientDNS01\Acme\AcmeAccount;

class AcmeEndpointNewAccount extends AcmeEndpoint {
  
  public function createRequest(
    AcmeNonce   $nonce = null,
    AcmeAccount $account = null,
    string      $method = 'POST' ): AcmeDirectoryRequest {
    return parent::createRequest( $nonce, $account, $method );
  }
}