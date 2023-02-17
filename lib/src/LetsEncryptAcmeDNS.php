<?php

namespace Takuya\LEClientDNS01;

use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\PKey\CSRSubject;
use Takuya\LEClientDNS01\Delegators\AcmePHPWrapper;
use Takuya\LEClientDNS01\PKey\CertificateWithPrivateKey;
use Takuya\LEClientDNS01\Plugin\DNS\DNSPlugin;

class LetsEncryptAcmeDNS {
  
  /** @var \Monolog\Logger */
  protected $logger;
  protected AcmePHPWrapper $acme_cli;
  
  public function __construct (
    public string    $owner_priv_key,
    public string    $owner_email,
    protected array  $domain_names,
    public DNSPlugin $dns,
    public string    $acme_uri = LetsEncryptACMEServer::STAGING
  ) {
    $this->domain_names = $this->validateDomainName( $domain_names );
    $this->acme_cli = $this->initAcmePHP( $this->acme_uri );
  }
  
  public function setLogger ( $logger ): void {
    $this->logger = $logger;
  }
  
  public function log ( $message, $level = 'debug' ): void {
    // expect monolog.
    $this->logger?->$level( $message );
  }
  
  protected function validateDomainName ( $domain_names ) {
    empty( $domain_names ) && throw new \RuntimeException( 'DNS must not be empty.' );
    usort( $domain_names, function( $a, $b ) { return strlen( $a ) > strlen( $b ); } );
    $base_name = parent_domain( $domain_names[0] );
    $same_origin = array_filter( $domain_names, function( $e ) use ( $base_name ) {
      return str_contains( $e, $base_name );
    } );
    if ( sizeof( $domain_names ) !== sizeof( $same_origin ) ) {
      throw new \RuntimeException( 'Currently, this Library only support SAME Origin.' );
    }
    return $domain_names;
  }
  
  protected function initAcmePHP ( $acme_uri ): AcmePHPWrapper {
    $owner_pkey = new AsymmetricKey( $this->owner_priv_key );
    $cli = new AcmePHPWrapper( $owner_pkey->privKey(), $acme_uri );
    $cli->newAccount( $this->owner_email );
    return $cli;
  }
  
  /**
   * @throws \Throwable
   */
  protected function newOrder ( AsymmetricKey $domain_pkey, callable $on_dns_wait = null ): CertificateWithPrivateKey {
    // CSR
    $dn = new CSRSubject( ...['commonName' => $this->domain_names[0], 'subjectAlternativeNames' => $this->domain_names] );
    // start lets encrypt ACMEv2 process
    $cli = $this->acme_cli;
    //
    $cli->newOrder( $this->domain_names );
    $challenges = $cli->getDnsChallenge();
    $task = $this->createChallengeTask( $challenges );
    $on_wait = $on_dns_wait ?? function( $name, $type, $content ) {
      $message = sprintf( '...wait ( %s, %s, %s...) for update TXT in SOA NS.'.PHP_EOL,
        $name, $type, substr( $content, '0', 5 ) );
      $this->log( $message );
    };
    $this->processDNSTask( $task, $on_wait );
    
    // Finalize order.
    $cli->finalizeOrderCertificate( $this->domain_names[0], $dn, $domain_pkey->privKey() );
    //// Get Result.
    return new CertificateWithPrivateKey(
      $domain_pkey->privKey(),
      $cli->certificateLastIssued()['cert'],
      $cli->certificateLastIssued()['intermediate']
    );
  }
  
  /**
   * @throws \Throwable
   */
  public function orderNewCert ( string   $domain_pkey_pem = null,
                                 callable $on_dns_wait = null ): CertificateWithPrivateKey {
    //
    $domain_key = $domain_pkey_pem ? new AsymmetricKey( $domain_pkey_pem ) : new AsymmetricKey();
    return $this->newOrder( $domain_key, $on_dns_wait );
  }
  
  /**
   * @return DNSChallengeTask[]|array
   */
  protected function createChallengeTask ( array $challenges ): array {
    $tasks = [];
    foreach ( $challenges as $domain => $challenge ) {
      $tasks[$domain] = new DNSChallengeTask( $challenge, $this->dns );
    }
    return $tasks;
  }
  
  public function challengeDNSAuthorization ( array $challenges ): bool {
    return $this->acme_cli->challengeDNSAuthorization( $challenges );
  }
  
  /**
   * @throws \Throwable
   */
  protected function processDNSTask ( $challenges, $on_wait ): void {
    /** @var \Fiber[] $fibers */
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
      $fibers[$key]->start( $challenge, $on_wait );
    }
    // wait
    foreach ( $fibers as $fiber ) {
      while(!$fiber->isTerminated()){
        $fiber->resume();
      }
    }
  }
}