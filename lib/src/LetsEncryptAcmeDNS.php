<?php

namespace Takuya\LEClientDNS01;

use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\PKey\CSRSubject;
use Takuya\LEClientDNS01\Delegators\AcmePHPWrapper;
use Takuya\LEClientDNS01\PKey\CertificateWithPrivateKey;
use Takuya\LEClientDNS01\Delegators\DnsPluginContract;
use Takuya\LEClientDNS01\Delegators\LetsEncryptServer;

class LetsEncryptAcmeDNS {
  
  /** @var \Monolog\Logger */
  protected $logger;
  
  public function __construct (
    public string            $priv_key,
    public string            $owner_email,
    protected array          $domain_names,
    public DnsPluginContract $dns,
  ) {
    $this->domain_names = $this->validateDomainName( $domain_names );
  }
  public function setLogger($logger): void {
    $this->logger=$logger;
  }
  public function log($message,$level='debug'){
    // expect monolog.
    $this->logger?->$level($message);
  }
  
  protected function validateDomainName ( $domain_names ) {
    empty( $domain_names ) && throw new \RuntimeException( 'DNS must not be empty.' );
    rsort( $domain_names );
    usort( $domain_names, function( $a, $b ) { return strlen( $a ) > strlen( $b ); } );
    $base_name = parent_domain($domain_names[0]);
    $same_origin = array_filter( $domain_names, function( $e ) use ( $base_name ) {
      return str_contains( $e, $base_name );
    } );
    if ( sizeof( $domain_names ) !== sizeof( $same_origin ) ) {
      throw new \RuntimeException( 'Currently, this Library only support SAME Origin.' );
    }
    return $domain_names;
  }
  
  protected function newOrder ( AsymmetricKey $domain_pkey,
                                string        $acme_uri,
                                callable      $on_dns_wait = null ): CertificateWithPrivateKey {
    // keys
    $owner_pkey = new AsymmetricKey( $this->owner_priv_key );
    $dn = new CSRSubject( ...['commonName' => $this->domain_names[0], 'subjectAlternativeNames' => $this->domain_names] );
    
    // start lets encrypt ACMEv2 process
    $cli = new AcmePHPWrapper( $owner_pkey->privKey(), $acme_uri );
    //
    $cli->newAccount( $this->owner_email );
    $cli->newOrder( $this->domain_names );
    $challenges = $cli->getDnsChallenge();
    $on_wait = $on_dns_wait ?? function( $name, $type, $content ) {
      $message = sprintf( '...wait ( %s, %s, %s...) for update TXT in SOA NS.'.PHP_EOL,
        $name, $type, substr( $content, '0', 5 ) );
      $this->log( $message );
    };
    $this->processDNSTask( $challenges, $on_wait );
    
    // Finalize order.
    $cli->finalizeOrderCertificate( $this->domain_names[0], $dn, $domain_pkey->privKey() );
    //// Get Result.
    $ret = $cli->certificateLastIssued();
    $cert_and_a_key = new CertificateWithPrivateKey( $domain_pkey->privKey(), $ret['cert'], $ret['intermediate'] );
    return $cert_and_a_key;
  }
  
  public function orderNewCert ( string   $domain_pkey_pem= null , $acme_uri = LetsEncryptACMEServer::STAGING,
                                 callable $on_dns_wait = null ): CertificateWithPrivateKey {
    $domain_key = $domain_pkey_pem ? new AsymmetricKey($domain_pkey_pem): new AsymmetricKey();
    return $this->newOrder( $domain_key, $acme_uri, $on_dns_wait );
  }
  
  protected function processDNSTask ( $challenges, $on_wait ) {
    /** @var \Fiber[] $fibers */
    $fibers = [];
    foreach (  $challenges as $key => $challenge) {
      $challenge->setDnsClient( $this->dns );
      $fibers[$key] = new \Fiber(function(DNSChallengeTask $task,callable $func):bool{
        $task->start( $func );
        return true;
      });
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