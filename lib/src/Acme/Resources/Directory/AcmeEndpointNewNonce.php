<?php

namespace Takuya\LEClientDNS01\Acme\Resources\Directory;

use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;
use Takuya\LEClientDNS01\Acme\Requests\AcmeDirectoryRequest;
use Takuya\LEClientDNS01\Acme\Requests\RequestNewNonceDirectoryRequest;

class AcmeEndpointNewNonce extends AcmeEndpoint {
  
  public function createRequest(
    AcmeNonce $nonce = null,
  ): AcmeDirectoryRequest {
    $nonce = $nonce ?? new AcmeNonce();
    return new RequestNewNonceDirectoryRequest($nonce,$this->getUrl());
  }
}
