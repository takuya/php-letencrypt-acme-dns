<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\AcmeAuthorizationChallenge;
use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;
use Takuya\LEClientDNS01\Acme\Http\Rs256JwsSigner;
use Takuya\LEClientDNS01\Acme\Base64URLEncode;

class ChallengeAuthorizeRequest extends AcmeOrderRequest {
  public function __construct(
    protected AcmeNonce                  $nonce,
    protected AcmeAccount                $account,
    protected AcmeAuthorizationChallenge $challenge,
    protected string                     $method = 'POST' ) {
    //
  }
  
  protected function protectedStr(): string {
    return Base64URLEncode::encode( json_encode( [
      "alg"   => "RS256",
      "kid"   => $this->account->kid(),
      "nonce" => $this->nonce->content(),      // 取得済みの Nonce
      "url"   => $this->challenge->getUrl(),   // order->challenges[idx] から取得したURL
    ] ) );
  }
  
  protected function emptyPayload():string {
    return Base64URLEncode::encode( json_encode( (object)[] ) );// empty payload body needs '{}'.
  }
  
  public function getBody(): string {
    $body = json_encode( [
      "protected" => $p1 = $this->protectedStr(),
      "payload"   => $p2 = $this->emptyPayload(),
      "signature" => Rs256JwsSigner::sign( $p1, $p2, $this->account->private_key_pem() ),
    ] );
    return $body;
  }
  
  public function getRequestUrl(): string {
    return $this->challenge->getUrl();
  }
}