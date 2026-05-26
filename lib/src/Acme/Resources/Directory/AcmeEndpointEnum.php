<?php

namespace Takuya\LEClientDNS01\Acme\Resources\Directory;

use Takuya\LEClientDNS01\Acme\Requests\RegisterNewAccountDirectoryRequest;
use Takuya\LEClientDNS01\Acme\Requests\RequestNewNonceDirectoryRequest;
use Takuya\LEClientDNS01\Acme\Requests\StartNewOrderDirectoryRequest;

enum AcmeEndpointEnum :string {
  case newAccount = AcmeEndpointNewAccount::class;
  case newNonce = AcmeEndpointNewNonce::class;
  case newOrder = AcmeEndpointNewOrder::class;
  case revokeCert = AcmeResouceRevokeCert::class;
  
  public function getRequestObjectClass(): string {
    return match($this){
      AcmeEndpointEnum::newNonce  => RequestNewNonceDirectoryRequest::class,
      AcmeEndpointEnum::newAccount=> RegisterNewAccountDirectoryRequest::class,
      AcmeEndpointEnum::newOrder  => StartNewOrderDirectoryRequest::class
    };
  }
}