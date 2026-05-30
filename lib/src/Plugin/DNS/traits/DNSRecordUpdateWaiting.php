<?php

namespace Takuya\LEClientDNS01\Plugin\DNS\traits;

use function Takuya\Utils\is_directly_resolve_allowed;

trait DNSRecordUpdateWaiting {
  
  use DNSQuery;
  
  public int $max_wait = 100;
  public int $time_on_each_sleep = 1;
  /**
   * @var false
   */
  public bool $enable_dns_check_at_waiting_for_update = true;
  
  public function waitForUpdated ( $name, $type, $content, callable $on_wait = null ): void {
    if ( $this->isDNSCheckEnabled() && $this->canResolveDirectly() ) {
      $this->waitAuthoriveNameServerUpdated($name, strtoupper($type ), $content, $on_wait ?? function() { } );
    } else {
      // wait 10 seconds, it might be enough for Cloudflare SOA primary NS and LE ACME Resolver.
      sleep( 1 );
      $on_wait && $on_wait( $name, $type, $content );
      sleep( 9 );
    }
  }
  
  protected function isDNSCheckEnabled (): bool {
    return $this->enable_dns_check_at_waiting_for_update;
  }
  
  
  protected function waitAuthoriveNameServerUpdated ( $name, $type, $content_expected, callable $on_wait ): void {
    $start = time();
    while ( !$this->assertDnsRecordContainsValues($name, $type, $content_expected ) ) {
      $on_wait( $name, $type, $content_expected );
      sleep( $this->time_on_each_sleep );
      if ( time() > $start + $this->max_wait ) {
        throw new \RuntimeException( 'gave up waiting for dns updated.' );
      }
    }
  }
  
  protected function assertDnsRecordContainsValues ( $name, $type, $expected_value ): bool {
    try{
      $content = $this->query( $name, $type );
      return !empty($content) && str_contains($content, $expected_value );
    }catch (\Exception){
      return false;
    }
  }
}