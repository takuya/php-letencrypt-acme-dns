<?php

namespace Takuya\LEClientDNS01;

use Takuya\LEClientDNS01\Plugin\DNS\DnsPluginContract;


class DNSChallengeTask {
  
  /**
   * @var AcmeDns01Record[]
   */
  protected array $records;
  
  public function __construct ( protected array $challenges, protected DnsPluginContract $dns ) {
    foreach ( $this->challenges as $item ) {
      $this->records[] = new AcmeDns01Record( $item['domain'], $item['payload'] );
    }
  }
  
  /**
   * @return array|AcmeDns01Record[]
   */
  public function getRecords (): array {
    return $this->records;
  }
  
  protected function updateDNSRecord (): void {
    foreach ( $this->records as $record ) {
      $this->dns->addDnsTxtRecord( $record->acme_domain_name(), $record->acme_content() );
    }
  }
  
  protected function verifyDNS ( LetsEncryptAcmeDNS $parent ): void {
    foreach ( $this->challenges as $challenge ) {
      $parent->challengeDNSAuthorization( $challenge );
    }
  }
  
  protected function waitDNS ( callable $on_each_wait = null ): void {
    foreach ( $this->records as $record ) {
      $this->dns->waitForUpdated( $record->acme_domain_name(), 'TXT', $record->acme_content(), $on_each_wait );
    }
  }
  
  protected function cleanUpDnsRecord (): void {
    foreach ( $this->records as $record ) {
      $this->dns->removeTxtRecord( $record->acme_domain_name(), $record->acme_content() );
    }
  }
  
  public function start ( LetsEncryptAcmeDNS $parent, callable $on_wait = null ): void {
    try {
      $this->updateDNSRecord();
      $this->waitDNS( $on_wait );
      $this->verifyDNS( $parent );
      $this->cleanUpDnsRecord();
    } catch (\Exception $e) {
      $this->cleanUpDnsRecord();
      throw $e;
    }
  }
  
  
}