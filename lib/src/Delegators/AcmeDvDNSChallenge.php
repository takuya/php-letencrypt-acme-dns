<?php

namespace Takuya\LEClientDNS01\Delegators;

use Takuya\LEClientDNS01\Acme\Resources\AcmeOrder;

class AcmeDvDNSChallenge {
  
  /**
   * @var AcmeDNSChallengeValue[]
   */
  protected array $values;
  
  public function __construct( protected AcmeDvCertificateOrder $order ) {
    foreach ( $this->order->getDomainNames() as $orderDomain ) {
      $this->values[$orderDomain] = $this->order->getDnsChallengeValue( $orderDomain );
    }
  }
  public function getChallengeValues():array {
    return $this->values;
  }
}