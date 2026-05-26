<?php

namespace Takuya\LEClientDNS01\Acme\Resources\Directory;

use Takuya\LEClientDNS01\Acme\Requests\AcmeNonce;
use Takuya\LEClientDNS01\Acme\Requests\AcmeDirectoryRequest;
use Takuya\LEClientDNS01\Acme\AcmeAccount;

class AcmeEndpointNewNonce extends AcmeEndpoint {
  
  public function createRequest(
    AcmeNonce $nonce = null,
    ?AcmeAccount $account = null,
    string    $method = 'GET'
  ): AcmeDirectoryRequest {
    $nonce = $nonce ?? new AcmeNonce();
    return parent::createRequest( $nonce, null, $method );
  }
}
