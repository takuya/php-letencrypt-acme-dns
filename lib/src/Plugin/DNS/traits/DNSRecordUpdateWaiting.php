<?php

namespace Takuya\LEClientDNS01\Plugin\DNS\traits;

use function Takuya\Utils\is_directly_resolve_allowed;
use function Takuya\Utils\dns_resolve;

trait DNSRecordUpdateWaiting {
  
  use DNSQuery;
  
  public int $time_max_wait = 60;
  public int $time_on_each_sleep = 1;
  /**
   * @var false
   */
  public bool $enable_authoritative_check = true;
  /**
   * @var int elapsed after api updated. wait for propagation for api update to dns resolved.
   */
  public int $time_try_resolve_after_update = 30;
  public function waitTxtUpdated( $name, $content, callable $on_wait = null ): void {
    $this->waitForUpdated($name, 'TXT', $content, $on_wait);
  }
  
  protected function waitForUpdated( $name, $type, $content, callable $on_wait = null ): void {
    if( $this->isDNSAuthoritativeCheckEnabled() && $this->canResolveDirectly() ) {
      $this->waitAuthoritativeNameServerUpdated( $name, strtoupper( $type ), $content, $on_wait ?? function() { } );
    } else {
      // wait 10 seconds, it might be enough for Cloudflare SOA primary NS and LE ACME Resolver.
      $this->waitResolverQueryDnsTxtUpdated( $name, $type, $content, $on_wait,
        $this->time_max_wait, $this->time_on_each_sleep, $this->time_try_resolve_after_update );
    }
  }
  
  protected function isDNSAuthoritativeCheckEnabled(): bool {
    return $this->enable_authoritative_check;
  }
  
  protected function waitResolverQueryDnsTxtUpdated( $name, $type, $content_expected, ?callable $on_wait, int $max_wait,
                                                     int $sleep_interval, int $try_resolve_after_sleep ): void {
    $start_at = time();
    do {
      // try once
      //   only ONE chance , we can try to get dns record considering "negative cache".
      //dump( [$start_at + $try_resolve_after_sleep, time(), $start_at + $try_resolve_after_sleep < time()] );
      if( $start_at + $try_resolve_after_sleep < time() ) {
        $dns_record = dns_get_record( $name, DNS_TXT );
        $dns_txt = $dns_record[0]['txt'] ?? '';
        dump($dns_txt);
        $updated_detected = str_contains( $dns_txt, $content_expected );
        $retry_after_ttl_expired = $dns_record[0]['ttl'] ?? 300;
        if( $updated_detected ) {
          break;
        } else {
          $try_resolve_after_sleep = $retry_after_ttl_expired;
        }
      }
      // sleep
      sleep( $sleep_interval );
      $on_wait && $on_wait( $name, $type, $content_expected, time() - $start_at );
    } while ( time() < $start_at + $max_wait );
  }
  
  protected function waitAuthoritativeNameServerUpdated( $name, $type, $content_expected, callable $on_wait ): void {
    $start = time();
    while ( !$this->assertDnsRecordContainsValues( $name, $type, $content_expected ) ) {
      $on_wait( $name, $type, $content_expected, time() - $start );
      sleep( $this->time_on_each_sleep );
      if( time() > $start + $this->time_max_wait ) {
        throw new \RuntimeException( 'gave up waiting for dns updated.' );
      }
    }
  }
  
  protected function assertDnsRecordContainsValues( $name, $type, $expected_value ): bool {
    try {
      $content = $this->query( $name, $type );
      return !empty( $content ) && str_contains( $content, $expected_value );
    } catch (\Exception) {
      return false;
    }
  }
}