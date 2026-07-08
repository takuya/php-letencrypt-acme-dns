<?php

namespace Takuya\LEClientDNS01\DnsCheck;

use function Takuya\Utils\is_directly_resolve_allowed;
use function Takuya\Utils\is_local_dns_available;
use Takuya\LEClientDNS01\DnsResolver\DnsResolver;
use Takuya\LEClientDNS01\DnsCheck\Strategy\DnsUpdateCheck;
use Takuya\LEClientDNS01\DnsCheck\Strategy\SoaSerialDnsCheck;
use Takuya\LEClientDNS01\DnsCheck\Strategy\VoidWorkDnsCheck;

trait ResolveDirectType {
  protected bool $is_directly_resolution_available;
  protected bool $is_local_resolver_found;
  
  protected function canResolveDirectly(): bool {
    return $this->is_directly_resolution_available ??= is_directly_resolve_allowed( 'a.root-servers.net' );
  }
  
  protected function canResolveUsingLocal(): bool {
    try {
      return $this->is_local_resolver_found ??= is_local_dns_available();
    } catch (\Exception) {
      return $this->is_local_resolver_found = false;
    }
  }
  
  protected function canLocalServerResolveSOA(): bool {
    $local_resolver = ResolveConf::parse()['nameserver'][0];
    $ret = DnsResolver::resolveDomainName( 'g.co', 'soa', $local_resolver );
    return
      0 < sizeof(
        array_filter(
          array_merge( $ret['ANSWER'], $ret['AUTHORITY'] ),
          fn( $e ) => $e['type'] == "SOA" )
      );
  }
  
  protected function selectStrategy():string {
    if( $this->canResolveDirectly() ) {
      return DnsUpdateCheck::class;
    } else if( $this->canResolveUsingLocal() && $this->canLocalServerResolveSOA() ) {
      return SoaSerialDnsCheck::class;
    } else {
      return VoidWorkDnsCheck::class;
    }
  }
  
}