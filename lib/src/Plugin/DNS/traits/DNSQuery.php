<?php

namespace Takuya\LEClientDNS01\Plugin\DNS\traits;

use function Takuya\Utils\dns_resolve;

trait DNSQuery {
  /**
   * @throws \Net_DNS2_Exception
   */
  public function query ( $name, $type ): string {
    $value = dns_resolve( $name, $type );
    //dump([$name,$type,$value]);
    return $value;
  }
  
  
}