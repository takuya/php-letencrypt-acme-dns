<?php

namespace Takuya\LEClientDNS01\DnsCheck\Strategy;


use function Takuya\Utils\dns_resolve;

class PublicDnsUpdateCheck extends DnsUpdateCheck {
  protected int $max_loop = 10;
  protected array $values_at_start;
  protected array $last_response;
  
  public function __construct(
    public string $domain_name,
    public string $type,
    public int    $timeout = 1,
    public string $public_dns = '1.1.1.1'
  ) {
    parent::__construct($this->domain_name,$this->type,$this->timeout);
  }
  
  protected function resolve(): array {
    $ret = dns_resolve( $this->domain_name, $this->type, $this->public_dns, $this->timeout );
    $lines = preg_split( '/\R/', $ret );
    sort( $lines );
    $ret = implode( PHP_EOL, $lines );
    if( empty( $ret ) ) throw new \RuntimeException( 'DNS resolution failed' );
    return ['domain' => $this->domain_name, 'type' => $this->type, 'rdata' => $ret];
  }
}