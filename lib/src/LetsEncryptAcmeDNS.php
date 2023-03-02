<?php

namespace Takuya\LEClientDNS01;

use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\PKey\CSRSubject;
use Takuya\LEClientDNS01\Delegators\AcmePHPWrapper;
use Takuya\LEClientDNS01\PKey\CertificateWithPrivateKey;
use Takuya\LEClientDNS01\Plugin\DNS\DNSPlugin;
use function Takuya\Utils\base_domain;
use function Takuya\Utils\parent_domain;
use function Takuya\Utils\assert_str_is_domain;


class LetsEncryptAcmeDNS {
  
  /** @var Monolog\Logger */
  protected $logger;
  protected AcmePHPWrapper $acme_cli;
  /** @var DnsPlugin[] */
  protected array $plugins = [];
  protected string $acme_uri;
  protected array $domain_names;
  
  /**
   * @return Account
   */
  public function getAccount (): Account {
    return $this->owner;
  }
  
  public function __construct (
    protected Account $owner,
  ) {
    $this->setAcmeURL();
    $this->acme_cli = $this->initAcmePHP( $this->acme_uri );
  }
  
  public function setDnsPlugin ( DnsPlugin $dns, string $target_domain_name = 'default' ) {
    $this->plugins[$target_domain_name] =$dns;
  }
  public function getDnsPlugin(string $target_domain_name='default'){
    return $this->plugins[$target_domain_name]
      ?? $this->plugins[base_domain( $target_domain_name )]
      ?? $this->plugins['default'];
  }
  public function setAcmeURL($acme_uri = LetsEncryptACMEServer::STAGING){
    $this->acme_uri = $acme_uri;
  }
  public function setDomainNames(array $domain_names){
    $this->domain_names = $this->validateDomainName( $domain_names );
  }
  protected function validateDomainName ( $domain_names ) {
    empty( $domain_names ) && throw new \RuntimeException( 'DNS must not be empty.' );
    usort( $domain_names, function( $a, $b ) { return strlen( $a ) > strlen( $b ); } );
    foreach ( $domain_names as $domain_name ) {
      $name = $domain_name;
      if (str_contains($name,'*.')){
        // skip wildcard
        $name = parent_domain($name);
      }
      if (!assert_str_is_domain($name)){
        throw new \InvalidArgumentException("'$domain_name' is not valid Domain Name." );
      }
    }
    return $domain_names;
  }
  
  protected function initAcmePHP ( $acme_uri ): AcmePHPWrapper {
    $private_key = $this->owner->private_key;
    $cli = new AcmePHPWrapper( $private_key, $acme_uri );
    // refresh account info
    if (empty($this->owner->key['n'])){
      $account_array = $cli->newAccount( $this->owner->contact[0] );
      $account_array['private_key'] = $private_key;
      $this->owner = new Account( ...$account_array );
    }
    return $cli;
  }
  
  public function setLogger ( $logger ): void {
    $this->logger = $logger;
  }
  
  /**
   * @throws \Throwable
   */
  public function orderNewCert ( string   $domain_pkey_pem = null,
                                 callable $on_dns_wait = null ): CertificateWithPrivateKey {
    //
    $this->isReady();
    return $this->newOrder(
      $domain_pkey_pem ? new AsymmetricKey( $domain_pkey_pem ) : new AsymmetricKey(),
      $on_dns_wait );
  }
  public function isReady(): bool {
    if(empty($this->domain_names)){
      throw new \LogicException('no Domain');
    }
    if(empty($this->plugins)){
      throw new \LogicException('no DNS Plugin');
    }
    return true;
  }
  
  /**
   * @throws \Throwable
   */
  protected function newOrder ( AsymmetricKey $domain_pkey, callable $on_dns_wait = null ): CertificateWithPrivateKey {
    // CSR
    $dn = new CSRSubject( ...['commonName' => $this->domain_names[0], 'subjectAlternativeNames' => $this->domain_names] );
    // start lets encrypt ACMEv2 process
    $cli = $this->acme_cli;
    $cli->newOrder( $this->domain_names );
    $chal = $cli->getDnsChallenge();
    $task = $this->createChallengeTask( $chal );
    $this->processDNSTask( $task, $on_dns_wait ?? $this->default_on_wait_callback() );
    
    // Finalize order.
    $cli->finalizeOrderCertificate( $this->domain_names[0], $dn, $domain_pkey->privKey() );
    //// Get Result.
    return new CertificateWithPrivateKey(
      $domain_pkey->privKey(),
      $cli->certificateLastIssued()['cert'],
      $cli->certificateLastIssued()['intermediate']
    );
  }
  private function default_on_wait_callback(): \Closure {
    return function( $name, $type, $content ) {
      $message = sprintf( '...wait ( %s, %s, %s...) for update TXT in SOA NS.'.PHP_EOL,
        $name, $type, substr( $content, '0', 5 ) );
      $this->log( $message );
    };
  }
  
  /**
   * @return DNSChallengeTask[]|array
   */
  protected function createChallengeTask ( array $challenges ): array {
    $tasks = [];
    foreach ( $challenges as $domain => $challenge ) {
      $tasks[$domain] = new DNSChallengeTask( $challenge, $this->getDnsPlugin($domain) );
    }
    return $tasks;
  }
  
  public function log ( $message, $level = 'debug' ): void {
    // expect monolog.
    $this->logger?->$level( $message );
  }
  
  /**
   * @throws \Throwable
   */
  protected function processDNSTask ( $challenges, $on_wait_from_user ): void {
    $fibers = [];
    foreach ( $challenges as $key => $challenge ) {
      //
      $func = function( DNSChallengeTask $task, callable $on_wait ): bool {
        $task->start( $this, $on_wait );
        return true;
      };
      $fibers[$key] = new \Fiber( $func );
    }
    // start
    foreach ( $challenges as $key => $challenge ) {
      $on_wait = function( $name, $type, $content ) use ( $on_wait_from_user ) {
        \Fiber::suspend( $content );
        $on_wait_from_user( $name, $type, $content );
      };
      /** @var \Fiber[] $fibers */
      $fibers[$key]->start( $challenge, $on_wait );
    }
    // wait
    foreach ( $fibers as $fiber ) {
      while ( !$fiber->isTerminated() ) {
        $fiber->resume();
      }
    }
  }
  
  public function challengeDNSAuthorization ( array $challenges ): bool {
    return $this->acme_cli->challengeDNSAuthorization( $challenges );
  }
}