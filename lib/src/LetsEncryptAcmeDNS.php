<?php

namespace Takuya\LEClientDNS01;

use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\PKey\CSRSubject;
use Takuya\LEClientDNS01\Delegators\LetsEncryptAcme;
use Takuya\LEClientDNS01\PKey\CertificateWithPrivateKey;
use Takuya\LEClientDNS01\Delegators\DnsAPIForLEClient;

class LetsEncryptAcmeDNS {
  
  public function __construct (
    public string            $priv_key,
    public string            $owner_email,
    public string            $domain_name,
    public DnsAPIForLEClient $dns,
  ) {
  }
  
  public function orderNewCert ( $acme_uri = LetsEncryptAcme::STAGING ): CertificateWithPrivateKey {
    // keys
    $owner_pky = new AsymmetricKey( $this->priv_key );
    // cert keys
    $domain_key = new AsymmetricKey();
    $csr = $domain_key->csr( new CSRSubject( ...['commonName' => $this->domain_name] ) );
    // dns updates
    $cleanup_dns_callback = function( $name ) { $this->dns->removeTxtRecord( $name ); };
    $dns_update_callback = function( $name, $content ) { $this->dns->changeDnsTxtRecord( $name, $content ); };
    
    // start lets encrypt ACMEv2 process
    $cli = new LetsEncryptAcme( $owner_pky->privKey(), $acme_uri );
    $cli->newAccount( $this->owner_email );
    $cli->startOderDnsChallenge( $this->domain_name, $dns_update_callback );
    $cli->processVerifyDNSAuth( $this->domain_name, $cleanup_dns_callback );
    $cli->finalizeOrderCertificate( $this->domain_name, $csr, $domain_key->privKey() );
    // Get Result.
    $ret = $cli->certificateLastIssued();
    $cert_and_a_key = new CertificateWithPrivateKey( $domain_key->privKey(), $ret['cert'], $ret['intermediate'] );
    return $cert_and_a_key;
  }
}