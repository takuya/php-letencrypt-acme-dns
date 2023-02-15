<?php

namespace Takuya\LEClientDNS01\Delegators;

use AcmePhp\Core\AcmeClient;
use AcmePhp\Core\Http\SecureHttpClientFactory;
use GuzzleHttp\Client as GuzzleHttpClient;
use AcmePhp\Core\Http\Base64SafeEncoder;
use AcmePhp\Ssl\Parser\KeyParser;
use AcmePhp\Ssl\Signer\DataSigner;
use AcmePhp\Core\Http\ServerErrorHandler;
use AcmePhp\Ssl\KeyPair;
use AcmePhp\Ssl\PublicKey;
use AcmePhp\Ssl\PrivateKey;
use AcmePhp\Ssl\DistinguishedName;
use AcmePhp\Ssl\CertificateRequest;
use Takuya\LEClientDNS01\PKey\AsymmetricKey;

class LetsEncryptAcme {
  const STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';
  const ACME_PREFIX = "_acme-challenge";
  
  protected AsymmetricKey $owner_pkey;
  protected AcmeClient $acme_php;
  protected \AcmePhp\Ssl\CertificateResponse $certificateResponse;
  protected array $last_challenge;
  
  public function __construct ( $user_private_key, $directory_url = self::STAGING ) {
    $this->owner_pkey = new AsymmetricKey( $user_private_key );
    $this->acme_php = $this->initialize_acme_client( $directory_url );
  }
  
  protected function initialize_acme_client ( $directory_url = self::STAGING ): AcmeClient {
    $factory = new SecureHttpClientFactory(
      new GuzzleHttpClient(),
      new Base64SafeEncoder(),
      new KeyParser(),
      new DataSigner(),
      new ServerErrorHandler()
    );
    $key = new KeyPair( new PublicKey( $this->owner_pkey->pubkey() ), new PrivateKey( $this->owner_pkey->privKey() ) );
    $httpCli = $factory->createSecureHttpClient( $key );
    return new AcmeClient( $httpCli, $directory_url );
  }
  
  public function newAccount ( $email ): array {
    return $this->acme_php->registerAccount( $email );
  }
  
  public function startOderDnsChallenge ( $domain_name, callable $dns_update = null ): void {
    $challenge = $this->getDnsChallenge( $domain_name );
    $dns01 = [];
    $dns01['challenge'] = $challenge->toArray();
    $dns01['acme']['domain'] = sprintf( "%s.%s", self::ACME_PREFIX, $dns01['challenge']['domain'] );
    $dns01['acme']['content'] = \base64_url_encode( hash( 'sha256', $dns01['challenge']['payload'], true ) );
    //
    $dns_update( $dns01['acme']['domain'], $dns01['acme']['content'] );
    $this->last_challenge = $dns01;
  }
  
  protected function getDnsChallenge ( $domain_name ) {
    $challenges = $this->acme_php->requestAuthorization( $domain_name );
    $found = null;
    foreach ( $challenges as $challenge ) {
      if ( $challenge->getType() == 'dns-01' ) {
        $found = $challenge;
        break;
      }
    }
    return $found;
  }
  
  public function cleanUpDNS ( callable $dns_update ): void {
  }
  
  public function processVerifyDNSAuth ( $domain_name, callable $dns_update ): array {
    try {
      $challenge = $this->getDnsChallenge( $domain_name );
      $ret = $this->acme_php->challengeAuthorization( $challenge );
    }catch (\Exception $e){
      $dns_update( $this->last_challenge['acme']['domain'], $this->last_challenge['acme']['content'] );
      throw $e;
    } finally {
      $dns_update( $this->last_challenge['acme']['domain'], $this->last_challenge['acme']['content'] );
    }
    return $ret;
  }
  
  public function finalizeOrderCertificate ( $domain_name, \OpenSSLCertificateSigningRequest $csr,
                                             $domain_private_key ): void {
    // AcmePHP はCSRに手間が多い。
    $dn = new DistinguishedName( ...openssl_csr_get_subject( $csr, false ) );
    $domain_pkey = new AsymmetricKey( $domain_private_key );
    $keypair = new KeyPair(
      new PublicKey( $domain_pkey->pubKey() ),
      new PrivateKey( $domain_pkey->privKey() )
    );
    $csr = new CertificateRequest( $dn, $keypair );
    
    $this->certificateResponse = $this->acme_php->requestCertificate( $domain_name, $csr );
  }
  
  public function certificateLastIssued (): array {
      $this->certificateResponse ?? throw new \RuntimeException( 'no order issued.' );
    return [
      // This is the certificate (public key)
      'cert' => $this->certificateResponse->getCertificate()->getPem(),
      'intermediate' => [
        // For Let's Encrypt, you will need the intermediate too
        $this->certificateResponse->getCertificate()->getIssuerCertificate()->getPEM(),
      ],
    ];
  }
}