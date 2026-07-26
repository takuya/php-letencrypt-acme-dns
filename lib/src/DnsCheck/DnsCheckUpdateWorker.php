<?php

namespace Takuya\LEClientDNS01\DnsCheck;

use Takuya\LEClientDNS01\DnsCheck\Strategy\SoaSerialDnsCheck;
use Takuya\LEClientDNS01\DnsCheck\Strategy\DnsUpdateCheck;
use Takuya\LEClientDNS01\DnsCheck\Strategy\VoidWorkDnsCheck;
use Takuya\LEClientDNS01\DnsCheck\Strategy\TTLFollowingDnsCheck;

class DnsCheckUpdateWorker {
  use ResolveDirectType;
  
  /** @var \Fiber[] */
  protected array $fibers;
  protected int $default_sleep_time_for_indirect = 60;
  protected int $default_sleep_time_for_direct = 1;
  protected int $sleep_interval;
  protected int $timeout = 30;
  
  public function __construct() {
  }
  
  public function setTimeout( int $time ): void {
    $this->timeout = $time;
  }
  
  public function setInterval( int $interval ): void {
    $this->sleep_interval = $interval;
  }
  
  protected function getSleepInterval(): int {
    // TODO:
    return $this->sleep_interval ??= (
      $this->canResolveDirectly() || $this->canResolveUsingLocal() )
      ? $this->default_sleep_time_for_direct : $this->default_sleep_time_for_indirect;
  }
  
  protected function addTask( \Fiber $f ): void {
    $this->fibers ??= [];
    $this->fibers[] = $f;
  }
  
  public function waitDnsUpdate(): void {
    $this->join();
  }
  
  public function selectStrategy(): string {
    if( $this->canResolveDirectly() ) {
      return DnsUpdateCheck::class;
    } else if( $this->canResolveUsingLocal() && $this->canLocalServerResolveSOA() ) {
      return SoaSerialDnsCheck::class;
    } else {
      return $this->timeout < 60 ? VoidWorkDnsCheck::class : TTLFollowingDnsCheck::class;
    }
  }
  
  public function addCheck( string $domain_name, string $type, ?callable $comparator=null ): void {
    $class = $this->selectStrategy();
    $checker = new $class( trim( $domain_name ), trim( $type ) );
    $checker->setLimit( intval( $this->timeout/$this->getSleepInterval() ) + 1 );
    $this->addTask( $checker->checkTask( $comparator ) );
  }
  
  public function start() {
    !$this->started() && array_map( fn( $f ) => $f->start(), $this->fibers );
  }
  
  protected function join(): void {
    $this->joinFibers();
  }
  
  protected function sleep(): void {
    sleep( $this->getSleepInterval() );
  }
  
  
  protected function joinFibers(): array {
    $this->start();
    $start = time();
    while ( !$this->finished() ) {
      //
      if( $start + $this->timeout < time() ) {
        $this->cancel();
      } else {
        $this->sleep();
      }
      //
      foreach ( $this->fibers as $fiber ) {
        if( $fiber->isTerminated() ) continue;
        $fiber->resume();
      }
    }
    return array_map( fn( $f ) => $f->getReturn(), $this->fibers );
  }
  
  protected function finished(): bool {
    /** @var \Fiber $f */
    foreach ( $this->fibers as $f ) {
      if( !$f->isTerminated() ) {
        return false;
      }
    }
    return true;
  }
  
  protected function cancel() {
    array_map( fn( $f ) => $f->throw( new \RuntimeException( 'Fiber Timeout' ) ), $this->fibers );
    throw new \RuntimeException( 'Worker timeout' );
  }
  
  protected function started(): bool {
    /** @var \Fiber $f */
    return array_reduce(
      array_map( fn( $f ) => $f->isStarted(), $this->fibers ),
      fn( $carry, $v ) => $carry && $v,
      true );
  }
}