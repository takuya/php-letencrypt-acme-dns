<?php

namespace Takuya\LEClientDNS01\DnsCheck\Strategy;


use function Takuya\Utils\is_local_dns_available;
use Takuya\LEClientDNS01\DnsResolver\DnsResolver;
use Takuya\LEClientDNS01\DnsCheck\ResolveConf;

class SoaSerialDnsCheck extends DnsUpdateCheck {
  protected int $max_loop = 10;
  protected string $sub;
  
  
  /**
   * 仮説。 DNSの変更検出は、 SOA Serialの値変化を見ていれば良いのではないか。 ランダムサブドメインでSerial変化を追いかけてみてはどうだろう
   * @param string $domain_name
   * @param string $type
   * @param int    $timeout
   */
  public function __construct(
    public string $domain_name,
    public string $type,
    public int    $timeout = 1
  ) {
    $this->sub = 'a';
    parent::__construct( $this->domain_name, $this->type, $this->timeout );
    if ($this->getStartValue()['serial']==0){
      throw new \RuntimeException('LocalServer omitting authority soa, gave up.');
    }
  }
  
  protected function next(): string {
    /**
     * php の愉快な仕様を活用する。
     * $s='a'; $s++;$s++;$s++;.. と繰り返せば、 a,b,c..z,aa,...az,ba,..zzになる。
     */
    return $this->sub++;
  }
  
  protected function next_domain() {
    return sprintf( "%s.%s", $this->next(), $this->domain_name );
  }
  
  protected function resolve(): array {
    $ret = $this->get_soa_serial();
    return ['domain' => $ret[0], 'type' => 'soa', 'serial' => $ret[1]];
  }
  
  public function isChanged(): bool {
    //dump( [$this->getStartValue(), $this->getLatestValue()] );
    return $this->getLatestValue()['serial'] > $this->getStartValue()['serial'];
  }
  protected function getLocalResolver() {
    $local_resolver = ResolveConf::parse()['nameserver'][0];
    return $local_resolver;
  }
  
  
  protected function get_soa_serial(): array {
    // soa 問合せで、ランダムサブドメインをやるとシリアル値が変わるのを追いかけられる。
    // DNS攻撃と大差ないけど、コレしかないんですよね。残念ながら
    if( is_local_dns_available() ) {
      $ret = DnsResolver::resolveDomainName( $d = $this->next_domain(), 'soa', $this->getLocalResolver(), 1 );
      $authority_has_serial = array_values(
        array_filter(
          array_merge( $ret['ANSWER'], $ret['AUTHORITY'] ),
          fn( $e ) => is_array( $e['rdata']
          ) ) );
      
      if( !empty( $authority_has_serial[0]['rdata']['serial'] ) ) {
        return [$d, $authority_has_serial[0]['rdata']['serial']];
      }else{
        return [$d, 0];
      }
    } else {
      throw new \RuntimeException( 'local dns server is not available.' );
    }
  }
  
}