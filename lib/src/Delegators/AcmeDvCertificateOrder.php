<?php

namespace Takuya\LEClientDNS01\Delegators;

use Takuya\LEClientDNS01\Acme\Resources\AcmeOrder;
use Takuya\LEClientDNS01\PKey\CSRSubject;

class AcmeDvCertificateOrder {
  
  protected AcmeOrder $body;
  /**
   * @var string[]
   */
  protected array $domain_names;
  
  public function __construct( AcmeOrder $order) {
    $this->body = $order;
  }
  
  public function setOrderDomains( array $domain_names ): void {
    $this->domain_names = $domain_names;
  }
  public function getDomainsInResponse():array {
    return array_map(fn($e)=>$e->value,array_filter($this->body->getIdentifiers(),fn($e)=>$e->type=='dns'));
  }
  public function getDomainNames():array {
    return $this->domain_names;
  }
  public function getDnsChallenge(string $orderDomain): AcmeDNSChallenge {
    return new AcmeDNSChallenge($orderDomain, $this->body->getAuthorization($orderDomain),$this->body->getAccount());
  }
  public function getAcmeOrder():AcmeOrder {
    return $this->body;
    
  }
}