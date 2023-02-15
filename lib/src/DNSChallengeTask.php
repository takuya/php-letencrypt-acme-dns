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
  
  public function __construct (
    
    array $challenge,
    AcmePHPWrapper $parent,
  ) {
    $this->challenges = $challenge;
    $this->parent = $parent;
    foreach ( $this->challenges as $item ) {
      $this->records[] = new AcmeDns01Record($item->getDomain(), $item->getPayload());
    }
  }
  public function setDnsClient(DnsAPIForLEClient $dns){
    $this->dns = $dns;
  }
  public function getRecords(){
    return $this->records;
  }
  
  public function updateDNSRecord(){
    foreach ( $this->records as $record){
      $this->dns->addDnsTxtRecord($record->acme_domain_name(),$record->acme_content());
    }
  }
  public function verifyDNS(){
    foreach ( $this->challenges as $challenge ) {
      $this->parent->challengeAuthorization($challenge);
    }
  }
  public function waitDNS(callable $on_wait=null){
    foreach ( $this->records as $record){
      $this->dns->waitForUpdated($record->acme_domain_name(),'TXT',$record->acme_content(),$on_wait);
    }
  }
  public function cleanUpDnsRecord(){
    foreach ( $this->records as $record){
      $this->dns->removeTxtRecord($record->acme_domain_name(),$record->acme_content());
    }
  }
  public function start(callable $on_wait=null){
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