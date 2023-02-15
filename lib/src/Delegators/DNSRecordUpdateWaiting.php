<?php

namespace Takuya\LEClientDNS01\Delegators;

trait DNSRecordUpdateWaiting {
  
  use DNSQuery;
  
  public int $max_wait = 100;
  /**
   * @var false
   */
  public bool $enable_dns_check_at_waiting_for_update = false;
  
  public function waitForUpdated ( $name, $type, $content, callable $on_wait = null ): void {
    if ( $this->enable_dns_check_at_waiting_for_update ) {
      $on_wait = $on_wait ?? function() { };
      $start = time();
      while ( !str_contains( $content, $this->query( $name, $type ) ) ) {
        $on_wait( $name, $type, $content );
        sleep( 1 );
        if ( time() > $start + $this->max_wait ) {
          throw new \RuntimeException( 'gave up waiting for dns updated.' );
        }
      }
      // After primary NS updated, wait for LE resolver.
      sleep( 7 );
    } else {
      // wait 10 seconds will be enough for Cloudflare SOA primary NS and LE ACME Resolver.
      sleep( 10 );
    }
  }
}