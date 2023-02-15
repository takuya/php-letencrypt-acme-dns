<?php

namespace Takuya\LEClientDNS01;

use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\PKey\CSRSubject;
use Takuya\LEClientDNS01\Delegators\AcmePHPWrapper;
use Takuya\LEClientDNS01\PKey\CertificateWithPrivateKey;
use Takuya\LEClientDNS01\Delegators\DnsPluginContract;
use Takuya\LEClientDNS01\Delegators\LetsEncryptServer;

class LetsEncryptAcmeDNS {
  
  public function __construct (
    public string            $priv_key,
    public string            $owner_email,
    protected array          $domain_names,
    public DnsPluginContract $dns,
  ) {
    $this->domain_names = $this->validateDomainName( $domain_names );
  }
  
  protected function validateDomainName ( $domain_names ) {
    empty( $domain_names ) && throw new \RuntimeException( 'DNS must not be empty.' );
    rsort( $domain_names );
    usort( $domain_names, function( $a, $b ) { return strlen( $a ) > strlen( $b ); } );
    $base_name = $domain_names[0];
    $same_origin = array_filter( $domain_names, function( $e ) use ( $base_name ) {
      return str_contains( $e, $base_name );
    } );
    if ( sizeof( $domain_names ) !== sizeof( $same_origin ) ) {
      throw new \RuntimeException( 'Currently, this Library only support SAME Origin.' );
    }
    return $domain_names;
  }
  
  public function orderNewCert ( $acme_uri = LetsEncryptServer::STAGING ): CertificateWithPrivateKey {
    // keys
    $owner_pky = new AsymmetricKey( $this->priv_key );
    // cert keys
    $domain_key = new AsymmetricKey();
    $dn = new CSRSubject( ...['commonName' => $this->domain_names[0], 'subjectAlternativeNames' => $this->domain_names] );
    
    // start lets encrypt ACMEv2 process
    $cli = new AcmePHPWrapper( $owner_pky->privKey(), $acme_uri );
    //
    $cli->newAccount( $this->owner_email );
    $cli->newOrder( $this->domain_names );
    $challenges = $cli->getDnsChallenge();
    $on_wait = null;
    //$on_wait = function( ...$args ) { dump( '...wait for SOA NS update TXT.' ); };
    //$on_wait = function( ...$args ) { dump( ['waiting',...$args]); };
    foreach ( $challenges as $challenge ) {
      $challenge->setDnsClient( $this->dns );
      $challenge->start( $on_wait );
    }
    // Finalize order.
    $cli->finalizeOrderCertificate( $this->domain_names[0], $dn, $domain_key->privKey() );
    //// Get Result.
    $ret = $cli->certificateLastIssued();
    $cert_and_a_key = new CertificateWithPrivateKey( $domain_key->privKey(), $ret['cert'], $ret['intermediate'] );
    return $cert_and_a_key;
  }
}