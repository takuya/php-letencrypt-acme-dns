<?php

namespace Takuya\LEClientDNS01\Acme\Resources;

use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpointEnum;
use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpointNewNonce;
use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpointNewAccount;
use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpointNewOrder;

class AcmeDirectory {
  protected object $directory;
  
  public function __construct(
    public string $url,
  ) {
  }
  
  public function directory() {
    return $this->directory = $this->directory ?? json_decode( file_get_contents( $this->url ) );
  }
  
  public function getDirectoryUrl( AcmeEndpointEnum $resourceName ): string {
    return $this->directory()->{$resourceName->name};
  }
  
  public function newNonceEndpoint():AcmeEndpointNewNonce {
    return new AcmeEndpointNewNonce($this,AcmeEndpointEnum::newNonce);
  }
  public function newAccountEndpoint():AcmeEndpointNewAccount {
    return new AcmeEndpointNewAccount($this,AcmeEndpointEnum::newAccount);
  }
  public function newOrderEndpoint():AcmeEndpointNewOrder {
    return new AcmeEndpointNewOrder($this,AcmeEndpointEnum::newOrder);
  }
  public function revokeCertURL() {
    return $this->getDirectoryUrl(AcmeEndpointEnum::revokeCert);
  }
}