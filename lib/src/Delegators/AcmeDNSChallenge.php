<?php

namespace Takuya\LEClientDNS01\Delegators;

use Takuya\LEClientDNS01\Acme\Resources\AcmeAuthorizationChallenge;
use Takuya\LEClientDNS01\Acme\Http\Rs256JwsSigner;
use function Takuya\Utils\base64_url_encode;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\AcmeChallengeTypeEnum;
use Takuya\LEClientDNS01\Acme\Resources\AcmeAuthorization;

class AcmeDNSChallenge {
  
  protected AcmeAuthorization $body;
  protected string $domain_name;
  protected AcmeAccount $account;
  protected AcmeChallengeTypeEnum $type = AcmeChallengeTypeEnum::DNS01;
  
  public function __construct( string $domain_name,AcmeAuthorization $acmeAuthorization, AcmeAccount $account) {
    $this->domain_name = $domain_name;
    $this->body = $acmeAuthorization;
    $this->account = $account;
  }
  public function getDomainName():string{
    return $this->domain_name;
  }
  
  public function getDnsValue(): string {
    $thumbprint = base64_url_encode( hash( 'sha256', Rs256JwsSigner::JwkString( $this->account->private_key_pem() ), true ) );
    $keyAuthorization = $this->body->getChallenge($this->type)->getAuthToken().'.'.$thumbprint;
    $dnsValue = base64_url_encode( hash( 'sha256', $keyAuthorization, true ) );
    return $dnsValue;
  }
}