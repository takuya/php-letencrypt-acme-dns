<?php

namespace Takuya\LEClientDNS01\Plugin\DNS\traits;

namespace Takuya\LEClientDNS01\Plugin\DNS\traits;

trait DNSRecordUpdateWaiting {
  
  use DNSQuery;
  
  public int $max_wait = 100;
  /**
   * @var false
   */
  public bool $enable_dns_check_at_waiting_for_update = false;
  
  public function waitForUpdated ( $name, $type, $content, callable $on_wait = null ): void {
    // wait 10 seconds will be enough for Cloudflare SOA primary NS and LE ACME Resolver.
    if ( $this->enable_dns_check_at_waiting_for_update ) {
      $on_wait = $on_wait ?? function() { };
      $start = time();
      while ( ! $this->assertRecord($name,$type,$content) ) {
        $on_wait( $name, $type, $content );
        sleep( 1 );
        if ( time() > $start + $this->max_wait ) {
          throw new \RuntimeException( 'gave up waiting for dns updated.' );
        }
      }
    }
  }
  protected function assertRecord( $name, $type, $content_expected): bool {
    $content = $this->query( $name, $type );
    //dump([$content_expected, $content,str_contains( $content ,$content_expected)]);
    return str_contains( $content ,$content_expected);
  }
}