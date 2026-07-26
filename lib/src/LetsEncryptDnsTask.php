<?php

namespace Takuya\LEClientDNS01;

use Takuya\LEClientDNS01\Delegators\AcmeDvWrapper;
use Takuya\LEClientDNS01\Delegators\AcmeDNSChallengeValue;
use function Takuya\Utils\base_domain;
use Takuya\LEClientDNS01\Delegators\AcmeDvDNSChallenge;
use Takuya\LEClientDNS01\Plugin\DNS\DnsPluginContract;
use Takuya\LEClientDNS01\DnsCheck\DnsCheckUpdateWorker;
use Takuya\LEClientDNS01\Plugin\DNS\DnsPluginStore;

class LetsEncryptDnsTask {
  protected DnsCheckUpdateWorker $dns_checker;
  public function __construct(
    protected AcmeDvDNSChallenge $challenge,
    protected DnsPluginStore $plugins,
    protected ?\Closure $on_each_dns_check=null,
    protected ?\Closure $on_all_dns_updated=null
  ) {
    $this->dns_checker = new DnsCheckUpdateWorker();
    foreach ( $this->challenge->getChallengeValues() as $value ) {
      $domain = $value->acme_dns_record()[0];
      $dns_value = $value->getDnsValue();
      $comparator = function($args)use($dns_value,$on_each_dns_check){
        //dump([
        //  'wait'=>$dns_value,
        //  'current'=>$args['now']['rdata'],
        //  'result'=>str_contains($args['now']['rdata'],$dns_value)
        //    || ( $on_each_dns_check &&$on_each_dns_check(array_merge(['dns_value'=>$dns_value],$args)))
        //  ] );
        return str_contains($args['now']['rdata'],$dns_value)
          || ( $on_each_dns_check &&$on_each_dns_check(array_merge(['dns_value'=>$dns_value],$args)));
      };
      $this->dns_checker->addCheck( $domain, $value->getType(), $comparator );
    }
  }
  
  protected function updateDnsRecord(): void {
    foreach ( $this->challenge->getChallengeValues() as $value ) {
      $dns_cli = $this->plugins->getDnsPlugin( $value->getChallengeDomainName() );
      $dns_cli->addDnsTxtRecord( ...$value->acme_dns_record() );
    }
  }
  
  protected function cleanUpDnsRecord(): void {
    foreach ( $this->challenge->getChallengeValues() as $value ) {
      $dns_cli = $this->plugins->getDnsPlugin( $value->getChallengeDomainName() );
      $dns_cli->removeTxtRecord( ...$value->acme_dns_record() );
      
    }
    //// 消えるのを待つ
    //$clean_up_check = new DnsCheckUpdateWorker();
    //foreach ( $this->challenge->getChallengeValues() as $value ) {
    //  $domain = $value->acme_dns_record()[0];
    //  $dns_value = $value->getDnsValue();
    //  $clean_up_check->addCheck( $domain, $value->getType(), function($args)use($dns_value){
    //    dump('wait for clean up dns :'.$args['counter']);
    //    return !str_contains($args['now']['rdata'],$dns_value);
    //  } );
    //}
    //$clean_up_check->waitDnsUpdate();
    
  }
  
  protected function waitDnsUpdated(): void {
    $this->dns_checker->waitDnsUpdate();
  }
  protected function onUpdated(): void {
    $fn = $this->on_all_dns_updated;
    $fn && $fn();
  }
  
  
  public function start(): void {
    try {
      $this->updateDNSRecord();
      $this->waitDnsUpdated();
      $this->onUpdated();
    } catch (\Exception $e) {
      throw $e;
    } finally {
      $this->cleanUpDnsRecord();
    }
  }
}