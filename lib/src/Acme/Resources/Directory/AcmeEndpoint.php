<?php

namespace Takuya\LEClientDNS01\Acme\Resources\Directory;

use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;

abstract class AcmeEndpoint {
  public function __construct(
    protected AcmeDirectory    $directory,
    protected AcmeEndpointEnum $name
  ) {
  }
  public function getUrl(): string {
    return $this->directory->getDirectoryUrl( $this->name );
  }
  
  
}