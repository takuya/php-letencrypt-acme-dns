<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\Resources\AcmeAuthorizationChallenge;

class ChallengeAuthorizeCheckRequest extends AcmeRequest {
  
  public string $method = 'GET';
  
  public function __construct( protected AcmeAuthorizationChallenge $challenge ) { }
  
  public function getBody(): string {
    return '';
  }
  
  public function getRequestUrl(): string {
    return $this->challenge->getUrl();
  }
}