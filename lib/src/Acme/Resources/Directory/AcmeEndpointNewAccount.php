<?php

namespace Takuya\LEClientDNS01\Acme\Resources\Directory;

use Takuya\LEClientDNS01\Acme\Requests\AcmeDirectoryRequest;
use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Requests\RegisterNewAccountDirectoryRequest;

class AcmeEndpointNewAccount extends AcmeEndpoint {
  
  public function createRequest(
    AcmeNonce   $nonce,
    AcmeAccount $account,
    string      $method = 'POST' ): AcmeDirectoryRequest {
    return new RegisterNewAccountDirectoryRequest($nonce,$account,$this->getUrl(),$method);
  }
}