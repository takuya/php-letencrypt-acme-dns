<?php

namespace Takuya\LEClientDNS01\Plugin\DNS\traits;

use function Takuya\Utils\dns_resolve;
use function Takuya\Utils\is_directly_resolve_allowed;

trait DNSQuery {
  
  public bool $is_directly_resolve_allowed;
  
  /**
   * @throws \Net_DNS2_Exception
   */
  public function query( $name, $type ):string {
    if( $this->canResolveDirectly() ) {
      $value = dns_resolve($name, $type);
    } else {
      $values = array_values(
        array_filter(
          array_map(
            fn( $e ) => $e['ip'] ?? '',
            dns_get_record(
              $name,
              match ( $type ) {
                "A" => DNS_A,
                default => DNS_ANY
              }))));
      $value = $values[0];
    }
    
    //dump([$name,$type,$value]);
    return $value;
  }
  
  public function canResolveDirectly():bool {
    if( ! isset($this->is_directly_resolve_allowed) ) {
      $this->is_directly_resolve_allowed = is_directly_resolve_allowed('www.google.com');
    }
    
    return $this->is_directly_resolve_allowed;
  }
}