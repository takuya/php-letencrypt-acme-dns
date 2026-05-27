<?php

namespace Takuya\LEClientDNS01\Delegators;


use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;
use Takuya\LEClientDNS01\Acme\AcmeClient;
use Takuya\LEClientDNS01\Account;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\AcmeOrder;
use Takuya\LEClientDNS01\Acme\Resources\AcmeChallengeTypeEnum;
use Takuya\LEClientDNS01\Acme\Resources\AcmeAuthorizationChallenge;
use Takuya\LEClientDNS01\PKey\CSRSubject;
use Takuya\LEClientDNS01\Acme\X509SSLCertificate;

/**
 * Acme Wrapper for DV-SSL, dns-01
 * - Order
 * - Certificate
 *   - CSR
 *   - Private key
 * - ChallengeTask(s)
 *    - domain name => task
 * - Account
 */
class AcmeDvWrapper {
  
  
  protected string $directory_url;
  protected AcmeClient $acme_cli;
  protected AcmeAccount $acme_account;
  protected AcmeDvCertificateOrder $order;
  protected X509SSLCertificate $issuedCertificate;
  
  public function __construct (string $directory_url ) {
    $this->directory_url = $directory_url;
    // cache AcmeClient becoase AcmeClient uses instance variable.
    $this->acme_cli = new AcmeClient(new AcmeDirectory($directory_url));
    $this->acme_cli->newNonce();
  }
  
  public function newAccount ( Account $account ):void {
    $this->acme_account = new AcmeAccount($account->email_address(),$account->getPrivateKey());
    $this->acme_cli->newAccount($this->acme_account);
    $account->setAccountUrl($this->acme_account->kid());
  }
  public function newOrder ( array $domain_names ): void {
    $order = $this->acme_cli->newOrder($this->acme_account,$domain_names );
    $this->order = new AcmeDvCertificateOrder($order);
    $this->order->setOrderDomains($domain_names);
  }
  /**
   * @return AcmeDNSChallenge[]
   */
  public function getDnsChallenge():array {
    $challenges = [];
    foreach ( $this->order->getDomainNames() as $orderDomain ) {
      $challenges[] = $this->order->getDnsChallenge($orderDomain);
    }
    return $challenges;
  }
  public function challengeAuthorization(string $domain_name):void {
    $this->acme_cli->challengeAuthorization($this->order->getAcmeOrder(), $domain_name);
  }
  
  public function createCSRSubject( array $domain_names,string $country_name ="JP", string $state = "Osaka"): CSRSubject {
    $dn = new CSRSubject( ...[
      'commonName'              => $domain_names[0],
      'subjectAlternativeNames' => $domain_names,
      'countryName'             => $country_name,
      'stateOrProvinceName'     => $state,
    ] );
    return $dn;
  }
  
  public function finalizeOrderCertificate (\OpenSSLCertificateSigningRequest $csr  ): void {
    $this->acme_cli->finalize($this->order->getAcmeOrder(),CSRSubject::CsrToPem($csr));
    $cert_pem = $this->acme_cli->getCertificate($this->order->getAcmeOrder());
    $this->issuedCertificate = new X509SSLCertificate($cert_pem);
  }
  
  public function certificateLastIssued (): array {
    $this->issuedCertificate ?? throw new \RuntimeException( 'no order issued.' );
    return [
      // This is the certificate (public key)
      'cert' => $this->issuedCertificate->exportLeafPem(),
      'intermediate' => [
        // For Let's Encrypt, you will need the intermediate too
        $this->issuedCertificate->intermediatesAsPem(),
      ],
    ];
  }
}