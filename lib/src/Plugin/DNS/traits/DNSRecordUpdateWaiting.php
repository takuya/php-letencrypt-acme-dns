<?php

namespace Takuya\LEClientDNS01\Plugin\DNS\traits;

trait DNSRecordUpdateWaiting {
  
  use DNSQuery;
  
  public int $max_wait = 100;
  public int $time_on_each_sleep = 1;
  /**
   * @var false
   */
  public bool $enable_dns_check_at_waiting_for_update = true;
  
  public function waitForUpdated ( $name, $type, $content, callable $on_wait = null ): void {
    $type = strtoupper( $type );
    if ( $this->isDNSCheckEnabled() ) {
      $this->waitUpdatedWithCheckingDNSQuery( $name, $type, $content, $on_wait ?? function() { } );
    } else {
      // wait 10 seconds will be enough for Cloudflare SOA primary NS and LE ACME Resolver.
      sleep( 10 );
    }
  }
  
  protected function isDNSCheckEnabled (): bool {
    return $this->enable_dns_check_at_waiting_for_update;
  }
  
  protected function waitUpdatedWithCheckingDNSQuery ( $name, $type, $content_expected, callable $on_wait ): void {
    $start = time();
    while ( !$this->assertRecord( $name, $type, $content_expected ) ) {
      $on_wait( $name, $type, $content_expected );
      sleep( $this->time_on_each_sleep );
      if ( time() > $start + $this->max_wait ) {
        throw new \RuntimeException( 'gave up waiting for dns updated.' );
      }
    }
  }
  
  protected function assertRecord ( $name, $type, $content_expected ): bool {
    $content = $this->query( $name, $type );
    return !empty($content) && str_contains( $content, $content_expected );
  }
}