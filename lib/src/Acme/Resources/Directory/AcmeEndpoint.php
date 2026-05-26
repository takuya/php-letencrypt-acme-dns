<?php

namespace Takuya\LEClientDNS01\Acme\Resources\Directory;

use Takuya\LEClientDNS01\Acme\Requests\AcmeDirectoryRequest;
use Takuya\LEClientDNS01\Acme\Requests\AcmeNonce;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;

abstract class AcmeEndpoint {
  public function __construct(
    protected AcmeDirectory    $directory,
    protected AcmeEndpointEnum $name
  ) {
  }
  
  public static function getResource( AcmeDirectory $directory, AcmeEndpointEnum $name ): AcmeEndpoint {
    //return new static( $directory, $name );
    return new $name->value( $directory, $name );
  }
  
  public function getUrl(): string {
    return $this->directory->getDirectoryUrl( $this->name );
  }
  
  public function createRequest( ?AcmeNonce   $nonce = null,
                                 ?AcmeAccount $account = null,
                                 string       $method = 'GET' ): AcmeDirectoryRequest {
    /** @var AcmeDirectoryRequest $acme_request_class */
    $acme_request_class = $this->name->getRequestObjectClass();
    return new $acme_request_class( $nonce, $account, $this, $method );
  }
  
  
}