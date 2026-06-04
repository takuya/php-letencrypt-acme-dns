<?php

namespace Takuya\LEClientDNS01;

use Takuya\LEClientDNS01\Delegators\AcmeDvWrapper;
use Takuya\LEClientDNS01\Delegators\AcmeDvWrapperStatus;
use Takuya\LEClientDNS01\Delegators\AcmeDNSChallenge;
use Takuya\LEClientDNS01\Plugin\DNS\DnsPluginContract;


class DNSChallengeTask {
  
  /**
   * @var AcmeDns01Record[]
   */
  protected array $records;
  
  /**
   * @param AcmeDNSChallenge[]  $challenges DNS01 challenge. Note:[*.example.tld, example.tld] should be tied in together.
   * @param DnsPluginContract   $dns
   */
  public function __construct ( protected array $challenges, protected DnsPluginContract $dns ) {
    foreach ( $challenges as $item ) {
      $this->records[$item->getDomainName()] = new AcmeDns01Record( $item->getDomainName(), $item->getDnsValue() );
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
      $this->dns->addDnsTxtRecord($record->acme_challenge_domain_name(), $record->acme_content() );
    }
  }
  
  protected function askAcmeServerAuthorizeVerifyDnsTxtRecord( callable $authorize_challenge ): void {
    // todo
    foreach ( $this->records as $identifier=> $acme_dns01_record ) {
      $authorize_challenge($identifier);
    }
  }
  protected function onUpdated( callable $onUpdated):void{
    $this->askAcmeServerAuthorizeVerifyDnsTxtRecord( $onUpdated );
  }
  
  protected function waitDNS ( callable $on_each_wait = null ): void {
    foreach ( $this->records as $record ) {
      $this->dns->waitForUpdated($record->acme_challenge_domain_name(), 'TXT', $record->acme_content(), $on_each_wait );
    }
  }
  
  protected function cleanUpDnsRecord (): void {
    foreach ( $this->records as $record ) {
      $this->dns->removeTxtRecord($record->acme_challenge_domain_name(), $record->acme_content() );
    }
  }
  
  public function start ( callable $challenge_authorize, callable $on_wait = null ): void {
    try {
      $this->updateDNSRecord();
      $this->waitDNS( $on_wait );
      $this->onUpdated($challenge_authorize);
    } catch (\Exception $e) {
      throw $e;
    } finally {
      $this->cleanUpDnsRecord();
    }
  }
  
  
}