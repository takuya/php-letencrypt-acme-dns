<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\Resources\AcmeOrder;

class FinalizeOrderStatusRequest extends AcmeRequest {
  
  public string $method = 'GET';
  
  public function __construct( protected AcmeOrder $order ) { }
  
  public function getBody(): string {
    return '';
  }
  
  public function getRequestUrl(): string {
    return $this->order->getOrderUrl();
  }
}