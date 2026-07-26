<?php

namespace Takuya\LEClientDNS01\Plugin\DNS;

use function Takuya\Utils\base_domain;
use function Takuya\Utils\parent_domain;

class DnsPluginStore {
  protected array $plugins = [];
  
  public function addDnsPlugin( DnsPluginContract $dns, string $domain = 'default' ): void {
    $this->plugins[$domain] = $dns;
  }
  
  public function getDnsPlugin( string $domain_name ): DnsPluginContract {
    for ( $d = $domain_name; $d != base_domain( $domain_name ); $d = parent_domain( $d ) ) {
      if( array_key_exists( $d, $this->plugins ) ) {
        return $this->plugins[$d];
      }
    }
    return $this->plugins['default'];
  }
  
}