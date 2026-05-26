<?php

namespace Takuya\LEClientDNS01\Acme\Resources;

use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpointEnum;
use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpoint;

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
  
  public function getResource( AcmeEndpointEnum $name = null ): AcmeEndpoint {
    return AcmeEndpoint::getResource( $this, $name );
  }
}