<?php

namespace Takuya\LEClientDNS01\Acme\Resources\Directory;


use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Requests\StartNewOrderDirectoryRequest;

class AcmeEndpointNewOrder extends AcmeEndpoint {
  public function createRequest( AcmeNonce $nonce , AcmeAccount $account): StartNewOrderDirectoryRequest {
    return new StartNewOrderDirectoryRequest($nonce, $account,$this->getUrl());
  }
}