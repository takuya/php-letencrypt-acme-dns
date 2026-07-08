<?php

namespace Takuya\LEClientDNS01\DnsCheck\Strategy;


use Takuya\LEClientDNS01\DnsResolver\DnsResolver;
use Takuya\LEClientDNS01\DnsCheck\ResolveConf;

class TTLFollowingDnsCheck extends DnsUpdateCheck {
  protected int $max_loop = 10;
  protected string $sub;
  
  
  /**
   * TTLの時間に従えばいいじゃない。
   * @param string $domain_name
   * @param string $type
   * @param int    $timeout
   */
  public function __construct(
    public string $domain_name,
    public string $type,
    public int    $timeout = 1
  ) {
    parent::__construct( $this->domain_name, $this->type, $this->timeout );
    $this->sub = 'a';
    if (empty($this->getStartValue()['ttl'])){
      throw new \RuntimeException('cant get ttl.');
    }
  }
  protected function resolve(): array {
    $ret = $this->get_A_record();
    return ['domain' => $ret[0], 'type' => 'a', 'ttl' => $ret[1]];
  }
  public function isChanged(): bool {
    return $this->getLatestValue()['ttl']<2;
  }
  
  protected function get_A_record():array {
    $ret = DnsResolver::resolveDomainName($this->domain_name,'a',$this->getLocalResolver());
    $rr = array_values( array_filter($ret['ANSWER']??[], fn($e)=>$e['type']=="A" ));
    return [$ret['QUERY'][0]['name'],$rr[0]['ttl']];
  }
  protected function getLocalResolver() {
    return ResolveConf::parse()['nameserver'][0];
  }
  
}