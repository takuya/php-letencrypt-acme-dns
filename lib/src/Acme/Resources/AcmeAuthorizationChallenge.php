<?php

namespace Takuya\LEClientDNS01\Acme\Resources;

use Takuya\LEClientDNS01\Acme\Requests\ChallengeAuthorizeRequest;
use Takuya\LEClientDNS01\Acme\Requests\AcmeNonce;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Requests\ChallengeAuthorizeCheckRequest;

class AcmeAuthorizationChallenge {
  public array $body;
  public function __construct( object $challenge ) {
    $this->body = (array)$challenge;
  }
  public function createRequest(AcmeNonce $nonce, AcmeAccount $account):ChallengeAuthorizeRequest {
    return new ChallengeAuthorizeRequest($nonce,$account,$this,);
  }
  public function createRequestForCheckPendingResult() {
    return new ChallengeAuthorizeCheckRequest($this);
    
  }
  public function getUrl():string {
    return $this->body['url']??'';
  }
  public function getAuthToken() {
    return $this->body['token'];
  }
}