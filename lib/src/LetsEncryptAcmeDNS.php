<?php

namespace Takuya\LEClientDNS01;

use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\Plugin\DNS\DNSPlugin;
use Takuya\LEClientDNS01\Delegators\AcmeDvWrapper;
use Takuya\LEClientDNS01\Delegators\AcmeDvWrapperStatus;
use Takuya\LEClientDNS01\Delegators\AcmeDNSChallengeValue;
use Takuya\LEClientDNS01\PKey\CertificateWithPrivateKey;
use function Takuya\Utils\base_domain;
use function Takuya\Utils\parent_domain;
use function Takuya\Utils\assert_str_is_domain;
use function Takuya\Utils\is_wildcard_domain;
use Takuya\LEClientDNS01\Plugin\DNS\DnsPluginStore;
use Takuya\LEClientDNS01\Delegators\AcmeDvDNSChallenge;
use MongoDB\BSON\PackedArray;
use Takuya\LEClientDNS01\DnsCheck\DnsCheckUpdateWorker;

class LetsEncryptAcmeDNS {
  
  /** @var \Monolog\Logger */
  protected                     $logger;
  protected AcmeDvWrapperStatus $acme_cli;
  /** @var DnsPlugin[] */
  protected DnsPluginStore $plugins;
  protected string $acme_uri;
  protected array $domain_names;
  protected CertificateWithPrivateKey $lastIssuedCert;
  protected array $dns_challenge_values;
  
  public function __construct( protected Account $owner ) {
    $this->setAcmeURL();
    $this->plugins = new DnsPluginStore();
  }
  
  public function setAcmeURL( $acme_uri = LetsEncryptACMEServer::STAGING ): void {
    $this->acme_uri = $acme_uri;
  }
  
  /**
   * @return Account
   */
  public function getAccount():Account {
    return $this->owner;
  }
  
  public function setDnsPlugin( DnsPlugin $dns, string $target_domain_name = 'default' ): void {
    $this->plugins->addDnsPlugin($dns,$target_domain_name);
  }
  
  public function setDomainNames( array $domain_names ) {
    $this->domain_names = static::validateDomainName($domain_names);
  }
  
  protected static function validateDomainName( $domain_names ) {
    empty($domain_names) && throw new \RuntimeException('DNS must not be empty.');
    usort($domain_names, fn ( $a, $b ) => strlen($a) <=> strlen($b) );
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
    return $this->lastIssuedCert = $this->newOrder(
      $domain_pkey_pem ? new AsymmetricKey( $domain_pkey_pem ) : new AsymmetricKey(),
      $on_dns_wait );
  }
  public function getLastIssuedCertificate(): CertificateWithPrivateKey {
    return $this->lastIssuedCert;
  }
  public function getLastChallengeDnsValue() :array {
    return $this->dns_challenge_values;
  }
  public function waitForCleanupDns(?callable $comparator=null): void {
    $dns_cleanup_check = new DnsCheckUpdateWorker();
    foreach ( $this->getLastChallengeDnsValue() as $domain => $value ){
      $comparator ??= function( ...$args ) use ( $value ) {
        $this->log(sprintf("... wait '%s' to be clean.: %s", $args[0]['now']['domain'],$args[0]['counter']));
        return !str_contains( $args[0]['now']['rdata'], $value );
      };
      $dns_cleanup_check->addCheck( $domain, 'TXT', $comparator);
    }
    //
    $dns_cleanup_check->waitDnsUpdate();
  }
  public function isReady(): bool {
    if(empty($this->domain_names)){ throw new \LogicException('no Domain');}
    if(empty($this->plugins)){ throw new \LogicException('no DNS Plugin'); }
    
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
    $this->processDnsChallenge($cli);
    $cli->finalizeOrderCertificate(
      $cli->createCSRSubject($this->domain_names)->opensslCsr( $domain_pkey->privKey(\OpenSSLAsymmetricKey::class) )
    );
    //// Get Result.
    return new CertificateWithPrivateKey(
      $domain_pkey->privKey(), $cli->certificateLastIssued()['cert'], $cli->certificateLastIssued()['intermediate']);
  }
  
  /**
   * @throws \Exception
   */
  protected function processDnsChallenge( AcmeDvWrapper $cli): void {
    $dnsTask = new LetsEncryptDnsTask(
      $cli->getDnsChallenge(),
      $this->plugins,
      function(...$args){
        $this->log(sprintf("... wait '%s' : %s", $d=$args[0]['now']['domain'],$args[0]['counter']));
        $this->dns_challenge_values[$d]=$args[0]['dns_value'];
      }
    );
    $dnsTask->start();
    $this->authorize($cli);
  }
  protected function authorize(AcmeDvWrapper $cli): void {
    $authorize = fn($identifier) => $cli->challengeAuthorization($identifier);
    foreach( $cli->getDnsChallenge()->getChallengeValues() as $challengeValue ){
      $authorize($challengeValue->getChallengeDomainName());
    }
  }
  
  public function log( $message, $level = 'debug' ):void {
    // expect monolog.
    $this->logger?->$level($message);
  }
}