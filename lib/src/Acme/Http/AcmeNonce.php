<?php

namespace Takuya\LEClientDNS01\Acme\Http;

use Psr\Http\Message\ResponseInterface;

class AcmeNonce  implements \Stringable {
  public function __construct(
    public ?string $nonce=null,
  ) { }
  public function updateNonce( ResponseInterface $res ):bool {
    $new_nonce = $res->getHeaderLine('Replay-Nonce')??'';
    if ($new_nonce){
      $this->nonce = $new_nonce;
      return true;
    }
    return false;
  }
  public function content():string {
    return $this->__toString();
  }
  public function __toString():string {
    return $this->nonce;
  }
}