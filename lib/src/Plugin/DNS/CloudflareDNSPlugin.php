<?php

namespace Takuya\LEClientDNS01\Plugin\DNS;

use Takuya\LEClientDNS01\Delegators\CloudflareDNSRecord;

class CloudflareDNSPlugin extends DNSPlugin {
  
  
  protected CloudflareDNSRecord $cloudflareWrapper;
  
  public function __construct ( $api_token, $zone_name ) {
    $this->cloudflareWrapper = new CloudflareDNSRecord( $api_token, $zone_name );
  }
  
  public function addDnsTxtRecord ( $domain, $content ): bool {
    $param = [
      'type' => 'TXT',
      'name' => $domain,
      'content' => $content,
      'proxied' => false,
    ];
    $this->cloudflareWrapper->addRecord( ...$param );
    return true;
  }
  
  public function removeTxtRecord ( $domain, $content = null ): bool {
    if ( $content == null ) {
      $txt_record = ['name' => $domain, 'type' => 'TXT', 'content' => $content];
      while ( $this->cloudflareWrapper->isExists( ...$txt_record ) ) {
        $this->cloudflareWrapper->deleteRecord( $this->cloudflareWrapper->getRecordId( ...$txt_record ) );
      }
    } else {
      $txt_record = ['name' => $domain, 'type' => 'TXT', 'content' => $content];
      $this->cloudflareWrapper->deleteRecord( $this->cloudflareWrapper->getRecordId( ...$txt_record ) );
    }
    return true;
  }
}