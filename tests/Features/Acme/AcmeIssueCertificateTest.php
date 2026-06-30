<?php

namespace Acme;

use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectoryEnum;
use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\AcmeClient;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;
use Takuya\LEClientDNS01\Acme\Http\AcmeHttpException;
use tests\Features\Acme\AcmeTestCase;
use Takuya\LEClientDNS01\Acme\Resources\AcmeChallengeTypeEnum;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
use Takuya\LEClientDNS01\Acme\Http\Rs256JwsSigner;
use function Takuya\Utils\base64_url_encode;
use Takuya\LEClientDNS01\PKey\CSRSubject;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;
use Takuya\LEClientDNS01\PKey\CertificateWithPrivateKey;
use Takuya\LEClientDNS01\Acme\X509SSLCertificate;
use function Takuya\Utils\sub_domain;

class AcmeIssueCertificateTest extends AcmeTestCase {
  protected string $sub_domain;
  protected AsymmetricKey $pkey;
  protected string $acme_challenge_name;
  protected string $acme_challenge_value;
  protected function setUp(): void {
    parent::setUp();
    //
    $str = RandomString::gen( 5, RandomString::LOWER );
    $this->sub_domain = "phpunit-{$str}.{$this->base_domain}";
    $this->pkey = new AsymmetricKey();
    $this->email = "admin@{$this->sub_domain}";
  }
  
  protected function cloudflare_dns_update( string $challenge_name, string $dnsValue ): void {
    $dns = new CloudflareDNSPlugin( $this->cf_api_token, $this->base_domain );
    $dns->enable_authoritative_check = true;
    $dns->addDnsTxtRecord( $challenge_name, $dnsValue );
    $dns->waitTxtUpdated( $challenge_name, $dnsValue );// blocking
    // save for remove
    $this->acme_challenge_name = $challenge_name;
    $this->acme_challenge_value = $dnsValue;
  }
  protected function cloudflare_dns_remove(string $name , string $content ): void {
    $cf = new CloudflareDNSPlugin( $this->cf_api_token, $this->base_domain );
    $cf->removeTxtRecord($name,$content);
    $cf->isExists(sub_domain($name));
  }
  
  protected function tearDown(): void {
    $this->cloudflare_dns_remove($this->acme_challenge_name,$this->acme_challenge_value);
    parent::tearDown();
  }
  
  
  protected function generate_csr( AsymmetricKey $d_key ): string {
    // finalize
    $dn = new CSRSubject( ...[
      'commonName'              => $this->sub_domain,
      'subjectAlternativeNames' => [$this->sub_domain],
      'countryName'             => 'JP',
      'stateOrProvinceName'     => 'Osaka',
    ] );
    $csrPem = $dn->getRequest( $d_key->privKey( \OpenSSLAsymmetricKey::class ) );
    return $csrPem;
  }
  
  public function test_homemade_acme_client_can_issue_certificate() {
    $dir = new AcmeDirectory( LetsEncryptACMEServer::STAGING );
    $cli = new AcmeClient( $dir );
    $cli->newNonce();
    $account = new AcmeAccount( $this->email, $this->pkey->privKey() );
    $cli->newAccount( $account );
    $new_order = $cli->newOrder( $account, [$this->sub_domain] );
    //
    $authorization = $new_order->getAuthorization( $this->sub_domain );
    $challenge = $authorization->getChallenge( AcmeChallengeTypeEnum::DNS01 );
    //
    $thumbprint = base64_url_encode( hash( 'sha256', Rs256JwsSigner::JwkString( $account->private_key_pem() ), true ) );
    $keyAuthorization = $challenge->getAuthToken().'.'.$thumbprint;
    $dnsValue = base64_url_encode( hash( 'sha256', $keyAuthorization, true ) );
    $challenge_dns = '_acme-challenge.'.$this->sub_domain;
    $this->cloudflare_dns_update( $challenge_dns, $dnsValue );
    //
    $cli->challengeAuthorization( $new_order, $this->sub_domain );
    //
    $cli->finalize( $new_order, $this->generate_csr( $domain_key = new AsymmetricKey() ) );
    $generated_cert_pem = $cli->getCertificate( $new_order );
    //
    $cert = new X509SSLCertificate( $generated_cert_pem );
    //['leaf' => $leaf, 'intermediates' => $chain] = $cert->toArray();
    //$storable_cert = new CertificateWithPrivateKey($leaf , $domain_key->privKey(), $chain);
    //$this->assertEquals($generated_cert_pem,$storable_cert->fullChain());
    $info = $cert->certInfo();
    $this->assertEquals("/CN={$this->sub_domain}",$info->name);
    $this->assertEquals($this->sub_domain,$info->subject['commonName']);
    $this->assertEquals("DNS:{$this->sub_domain}",$info->extensions['subjectAltName']);
  }
}