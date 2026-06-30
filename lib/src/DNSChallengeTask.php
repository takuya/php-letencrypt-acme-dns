<?php

namespace Takuya\LEClientDNS01;

use Takuya\LEClientDNS01\Delegators\AcmeDvWrapper;
use Takuya\LEClientDNS01\Delegators\AcmeDvWrapperStatus;
use Takuya\LEClientDNS01\Delegators\AcmeDNSChallengeValue;
use Takuya\LEClientDNS01\Plugin\DNS\DnsPluginContract;


class DNSChallengeTask {
  
  protected array $records;
  
  /**
   * @param AcmeDNSChallengeValue[] $dns_challenge_values DNS01 challenge. Note:[*.example.tld, example.tld] should be tied in together.
   * @param DnsPluginContract       $dns
   */
  public function __construct (  array $dns_challenge_values, protected DnsPluginContract $dns ) {
    foreach ( $dns_challenge_values as $item ) {
      [$dns_name,$dns_value] = $item->acme_dns_record();
      $identifier = $item->getChallengeDomainName();
      $this->records[] = ['identifier'=>$identifier, 'dns_name'=>$dns_name, 'dns_value'=>$dns_value];
    }
  }
  
  /**
   * @return array
   */
  public function getRecords (): array {
    return array_map(fn($e)=> [$e['dns_name'],$e['dns_value']],$this->records);
  }
  
  protected function updateDNSRecord (): void {
    foreach ( $this->getRecords() as $record ) {
      $this->dns->addDnsTxtRecord(...$record );
    }
  }
  
  protected function askAcmeServerAuthorizeVerifyDnsTxtRecord( callable $authorize_challenge ): void {
    // todo
    foreach ( $this->records as $record ) {
      $authorize_challenge($record['identifier']);
    }
  }
  protected function onUpdated( callable $onUpdated):void{
    $this->askAcmeServerAuthorizeVerifyDnsTxtRecord( $onUpdated );
  }
  
  protected function waitDNS ( callable $on_each_wait = null ): void {
    /**
     * When Wildcard Challenge.
     *  [example.tld. *.example.tld] require same domain _acme-challenge.example.tld that has ２ TXT record .
     *  When direct resolve blocked, we should check TXTs per domain to prevent Dirty cache of TTL.
     */
    foreach ( $this->getRecords() as $record ) {
      $this->dns->addDnsTxtRecord(...$record );
    }
    
    //$getRecordsPerDomainName = function ():array {
    //  $update_domains = [];
    //  foreach ( $this->getRecords() as $record ) {
    //    $domain_name =$record[0];
    //    $update_domains[$domain_name][]=$record;
    //  }
    //  dump($update_domains);
    //  return $update_domains;
    //};
    //foreach ( $getRecordsPerDomainName() as $domain_name=> $records ) {
    //  $tmp = $this->dns->time_try_resolve_after_update;
    //  //dump($domain_name);
    //  foreach ( $records as $idx=>$record ) {
    //    $this->dns->waitTxtUpdated(...[...$record,$on_each_wait]);
    //    //if ($idx>1){
    //    //  $this->dns->time_try_resolve_after_update=0;
    //    //}
    //  }
    //  //$this->dns->time_try_resolve_after_update=$tmp;
    //}
  }
  
  protected function cleanUpDnsRecord (): void {
    foreach ( $this->getRecords() as $identifier=> $record ) {
      $this->dns->removeTxtRecord(...$record );
    }
  }
  
  public function start ( callable $challenge_authorize, callable $on_wait = null ): void {
    try {
      //$this->updateDNSRecord();
      $this->waitDNS( $on_wait );
      $this->onUpdated($challenge_authorize);
    } catch (\Exception $e) {
      throw $e;
    } finally {
      $this->cleanUpDnsRecord();
    }
  }
  
  
}