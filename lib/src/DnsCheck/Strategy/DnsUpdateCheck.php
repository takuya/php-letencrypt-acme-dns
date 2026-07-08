<?php

namespace Takuya\LEClientDNS01\DnsCheck\Strategy;


use function Takuya\Utils\dns_resolve;

class DnsUpdateCheck {
  protected int $max_loop = 10;
  protected array $values_at_start;
  protected array $last_response;
  
  public function __construct(
    public string $domain_name,
    public string $type,
    public int    $timeout = 1
  ) {
    $this->values_at_start = $this->resolve();
  }
  
  protected function resolve(): array {
    $ret = dns_resolve( $this->domain_name, $this->type, null, $this->timeout );
    $lines = preg_split( '/\R/', $ret );
    sort( $lines );
    $ret = implode( PHP_EOL, $lines );
    if( empty( $ret ) ) throw new \RuntimeException( 'DNS resolution failed' );
    return ['domain' => $this->domain_name, 'type' => $this->type, 'rdata' => $ret];
  }
  
  public function check( ?callable $callback ): \Fiber {
    return $this->waitWithPolling( $callback );
  }
  
  protected function waitWithPolling( ?callable $callback ): \Fiber {
    return $this->pollingDnsWorker( $callback );
  }
  
  public function getLimit(): int {
    return $this->max_loop;
  }
  public function setLimit(int $max_loop):void {
    $this->max_loop = $max_loop;
  }
  
  public function getStartValue(): array {
    return $this->values_at_start;
  }
  
  public function getLatestValue(): array {
    return $this->last_response;
  }
  
  public function isChanged(): bool {
    return $this->getLatestValue()['rdata'] != $this->getStartValue()['rdata'];
  }
  
  protected function pollingDnsWorker( ?callable $callback ): \Fiber {
    return new \Fiber( function() use ( $callback ) {
      for ($cnt = 0; $cnt <= $this->getLimit(); $cnt++) {
        \Fiber::suspend();
        //
        $this->last_response = $this->resolve();
        //
        $callback && $callback( $this->getLatestValue(), $this->getStartValue(),$cnt );
        if( $this->isChanged() ) {
          break;
        }
      }
      return [
        $this->isChanged(),
        $this->getLatestValue(),
      ];
    } );
  }
}