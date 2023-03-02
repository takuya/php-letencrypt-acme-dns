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
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use Takuya\LEClientDNS01\DNSChallengeTask;
use Takuya\LEClientDNS01\PKey\CSRSubject;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;

class AcmePHPWrapper {

  
  protected AsymmetricKey $owner_pkey;
  protected string $directory_url;
  protected \AcmePhp\Ssl\CertificateResponse $certificateResponse;
  protected \AcmePhp\Core\Protocol\CertificateOrder $challenges;
  protected \AcmePhp\Core\Protocol\CertificateOrder $order;
  protected AcmeClient $acme_php_client;
  
  public function __construct ( $user_private_key, $directory_url = LetsEncryptACMEServer::STAGING ) {
    $this->owner_pkey = new AsymmetricKey( $user_private_key );
    $this->directory_url = $directory_url;
    // cache AcmeClient becoase AcmeClient uses instance variable.
    $this->acme_php_client = $this->initialize_acme_client( $this->directory_url );
  }
  
  protected function initialize_acme_client ( $directory_url  ): AcmeClient {
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
  
  protected function send_request ( $name, ...$args ) {
    /** @var \GuzzleHttp\Exception\ServerException $prev */
    $max_retry = 10;
    $error = null;
    foreach ( range( 0, $max_retry - 1 ) as $tried ) {
      try {
        return $this->acme_php_client->{$name}( ...$args );
      } catch (\AcmePhp\Core\Exception\AcmeCoreServerException $error) {
        if ( get_class($prev = $error->getPrevious()) !== \GuzzleHttp\Exception\ServerException::class){
          throw  $error;
        }
        $value = $prev->getResponse()->getHeader( 'retry-after' );
        $retry_after = !empty( $value ) ? $value[0] : 10;
        if ( $retry_after < 120 ) {// 120sec未満なら待つ。
          //dump($retry_after);
          sleep( $retry_after );
        } else {
          throw $error;
        }
      }
    }
    throw $error;
  }
  
  public function newAccount ( $email ): array {
    return $this->send_request('registerAccount',$email);
  }
  
  public function newOrder ( array $domain_names ): void {
    $this->order = $this->send_request('requestOrder',$domain_names);
  }
  
  public function getDnsChallenge (): array {
    $challenges_per_domain = $this->dnsChallengeInCertOrder();
    $to_array = [];
    foreach ( $challenges_per_domain as $domain=>$challenges ) {
      $to_array[$domain] = array_map(fn(AuthorizationChallenge $e)=>$e->toArray(),$challenges);;
    }
    return $to_array;
  }
  
  
  protected function dnsChallengeInCertOrder(): array {
    $available_challenges = $this->order->getAuthorizationsChallenges();
    $found = [];
    // find dns-01 challenge.
    foreach ($available_challenges as $challenges_per_domain){
      foreach ( $challenges_per_domain as $item ) {
        if ( $item->getType() == 'dns-01' ) {
          $found[] = $item;
        }
      }
    }
    // store challenges by domain name;
    $dns_challenges=[];
    foreach ( $found as $item ) {
      $dns_challenges[$item->getDomain()][]=$item;
    }
    // array of array
    return $dns_challenges;
  }
  public function challengeDNSAuthorization( array $challenge ): bool {
    $acme_php_challenge = AuthorizationChallenge::fromArray($challenge);
    $ret = $this->send_request('challengeAuthorization',$acme_php_challenge);
    return $ret['status'] == 'valid';
  }
  
  
  public function finalizeOrderCertificate ( $domain_name, CSRSubject $dn,
                                             $domain_private_key ): void {
    $acme_csr = $this->createCSR($dn,$domain_private_key);
    $this->certificateResponse = $this->send_request('finalizeOrder',$this->order,$acme_csr);
  }
  protected function createCSR(CSRSubject $dn, $domain_private_key): CertificateRequest {
    // AcmePHP はCSRに手間が多い。 openssl_csr_new がSAN 非対応のため。
    $dn = new DistinguishedName( ...$dn->toArray() );
    $domain_pkey = new AsymmetricKey( $domain_private_key );
    $keypair = new KeyPair( new PublicKey( $domain_pkey->pubKey() ),new PrivateKey( $domain_pkey->privKey() ) );
    $acme_csr = new CertificateRequest( $dn, $keypair );
    return $acme_csr;
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