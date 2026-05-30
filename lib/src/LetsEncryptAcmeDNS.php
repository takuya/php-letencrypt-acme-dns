<?php

namespace Takuya\LEClientDNS01;

use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\Plugin\DNS\DNSPlugin;
use Takuya\LEClientDNS01\Delegators\AcmeDvWrapper;
use Takuya\LEClientDNS01\Delegators\AcmeDvWrapperStatus;
use Takuya\LEClientDNS01\Delegators\AcmeDNSChallenge;
use Takuya\LEClientDNS01\PKey\CertificateWithPrivateKey;
use function Takuya\Utils\base_domain;
use function Takuya\Utils\parent_domain;
use function Takuya\Utils\assert_str_is_domain;

class LetsEncryptAcmeDNS {
  
  /** @var \Monolog\Logger */
  protected                     $logger;
  protected AcmeDvWrapperStatus $acme_cli;
  /** @var DnsPlugin[] */
  protected array $plugins = [];
  protected string $acme_uri;
  protected array $domain_names;
  
  public function __construct( protected Account $owner, ) {
    $this->setAcmeURL();
  }
  
  public function setAcmeURL( $acme_uri = LetsEncryptACMEServer::STAGING ) {
    $this->acme_uri = $acme_uri;
  }
  
  /**
   * @return Account
   */
  public function getAccount():Account {
    return $this->owner;
  }
  
  public function setDnsPlugin( DnsPlugin $dns, string $target_domain_name = 'default' ) {
    $this->plugins[$target_domain_name] = $dns;
  }
  
  public function setDomainNames( array $domain_names ) {
    $this->domain_names = static::validateDomainName($domain_names);
  }
  
  protected static function validateDomainName( $domain_names ) {
    empty($domain_names) && throw new \RuntimeException('DNS must not be empty.');
    usort($domain_names, function ( $a, $b ) { return strlen($a) <=> strlen($b); });
    foreach ($domain_names as $domain_name) {
      $name = $domain_name;
      if( str_contains($name, '*.') ) {
        // skip wildcard
        $name = parent_domain($name);
      }
      if (!assert_str_is_domain($name)){
        throw new \InvalidArgumentException("'{$domain_name}' is not valid Domain Name." );
      }
    }
    
    return $domain_names;
  }
  
  public function setLogger ( $logger ): void {
    $this->logger = $logger;
  }
  
  public function orderNewCert ( string   $domain_pkey_pem = null,
                                 callable $on_dns_wait = null ): CertificateWithPrivateKey {
    //
    $this->isReady();
    //
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
  protected function newOrder( AsymmetricKey $domain_pkey, callable $on_dns_wait = null ):CertificateWithPrivateKey {
  
    // // start lets encrypt ACMEv2 process
    $cli = new AcmeDvWrapper($this->acme_uri);
    $cli->newAccount($this->owner);
    $cli->newOrder($this->domain_names);
    $challenges = $cli->getDnsChallenges();
    // dns task
    $tasks = $this->createChallengeTasks($challenges);// ここ複数形になるんだっけ？　複数形より複数形のタスクを定義したほうが・・・
    // ここ DNS タスクで切り離さないと、 try-catch でもとに戻せない??
    $this->processDNSTask($tasks, $cli,  $on_dns_wait ?? $this->default_on_wait_callback());
    $cli->finalizeOrderCertificate(
      $cli->createCSRSubject($this->domain_names)->opensslCsr(
        $domain_pkey->privKey(\OpenSSLAsymmetricKey::class)));
    //// Get Result.
    return new CertificateWithPrivateKey(
      $domain_pkey->privKey(), $cli->certificateLastIssued()['cert'], $cli->certificateLastIssued()['intermediate']);
  }
  
  /**
   * @return DNSChallengeTask[]
   */
  protected function createChallengeTasks( array $challenges ):array {
    $tasks = [];
    foreach ($challenges as $domain => $challenge) {
      /** @var AcmeDNSChallenge $challenge */
      $tasks[$domain] = new DNSChallengeTask([$challenge], $this->getDnsPlugin($domain));
    }
    return $tasks;
  }
  
  public function getDnsPlugin( string $target_domain_name = 'default' ) {
    return $this->plugins[$target_domain_name] ??
           $this->plugins[base_domain($target_domain_name)] ?? $this->plugins['default'];
  }
  
  /**
   * @throws \Throwable
   */
  protected function processDNSTask ( array $challenges, AcmeDvWrapper $cli , callable $on_wait_from_user ): void {
    $fibers = [];
    foreach ( $challenges as $key => $challenge ) {
      //
      $func = function( AcmeDvWrapper $cli, DNSChallengeTask $task, callable $on_wait ): bool {
        $task->start( fn($identifier)=> $cli->challengeAuthorization($identifier) , $on_wait );
        return true;
      };
      $fibers[$key] = new \Fiber( $func );
    }
    // start
    foreach ( $challenges as $key => $challenge ) {// TODO 見通しが悪い
      $on_wait = function( $name, $type, $content ) use ( $on_wait_from_user ) {
        \Fiber::suspend( $content );
        $on_wait_from_user( $name, $type, $content );
      };
      /** @var \Fiber[] $fibers */
      $fibers[$key]->start( $cli , $challenge, $on_wait );
    }
    // wait
    foreach ( $fibers as $fiber ) {
      while ( !$fiber->isTerminated() ) {
        $fiber->resume();
      }
    }
  }
  
  private function default_on_wait_callback():\Closure {
    return function ( $name, $type, $content ) {
      $message = sprintf(
        '...wait ( %s, %s, %s...) for update TXT in SOA NS.'.PHP_EOL,
        $name,
        $type,
        substr($content, '0', 5));
      $this->log($message);
    };
  }
  
  public function log( $message, $level = 'debug' ):void {
    // expect monolog.
    $this->logger?->$level($message);
  }
}