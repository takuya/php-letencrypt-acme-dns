<?php

namespace Takuya\LEClientDNS01\Delegators;

trait DNSQuery {
  public function query ( $name, $type ) {
    // ** TODO dig 依存を外す。
    $ns = \domain_ns( $name );
    $cmd = "dig '${name}' ${type} +short @{$ns}";
    $content = `{$cmd}`;
    $content = str_replace( '"', '', trim( $content ) );
    return $content;
  }
  
  
}