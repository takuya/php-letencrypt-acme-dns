<?php

namespace Takuya\LEClientDNS01;

use AcmePhp\Core\Protocol\AuthorizationChallenge;
use Takuya\LEClientDNS01\Delegators\AcmePHPWrapper;
use Takuya\LEClientDNS01\Delegators\DnsAPIForLEClient;


class DNSChallengeTask {
  
  /**
   * @var AcmeDns01Record[]
   */
  protected array $records;
  protected DnsAPIForLEClient $dns;
  /** @var AuthorizationChallenge[] */
  protected array $challenges;
  protected AcmePHPWrapper $parent;
  
  public function __construct ( array $challenge, AcmePHPWrapper $parent, ) {
    $this->challenges = $challenge;
    $this->parent = $parent;
    foreach ( $this->challenges as $item ) {
      $this->records[] = new AcmeDns01Record( $item->getDomain(), $item->getPayload() );
    }
  }
  
  public function setDnsClient ( DnsAPIForLEClient $dns ): void {
    $this->dns = $dns;
  }
  
  /**
   * @return array|AcmeDns01Record[]
   */
  public function getRecords(): array {
    return $this->records;
  }
  
  protected function updateDNSRecord(): void {
    foreach ( $this->records as $record){
      $this->dns->addDnsTxtRecord($record->acme_domain_name(),$record->acme_content());
    }
  }
  protected function verifyDNS(): void {
    foreach ( $this->challenges as $challenge ) {
      $this->parent->challengeAuthorization($challenge);
    }
  }
  protected function waitDNS(callable $on_wait=null): void {
    foreach ( $this->records as $record){
      $this->dns->waitForUpdated($record->acme_domain_name(),'TXT',$record->acme_content(),$on_wait);
    }
  }
  protected function cleanUpDnsRecord(): void {
    foreach ( $this->records as $record){
      $this->dns->removeTxtRecord($record->acme_domain_name(),$record->acme_content());
    }
  }
  public function start(callable $on_wait=null): void {
    try{
      $this->updateDNSRecord();
      $this->waitDNS($on_wait);
      $this->verifyDNS();
      $this->cleanUpDnsRecord();
    }catch (\Exception $e){
      $this->cleanUpDnsRecord();
      throw $e;
    }
  }
  
  
  
  
}