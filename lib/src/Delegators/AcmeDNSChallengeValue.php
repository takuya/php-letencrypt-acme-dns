<?php

namespace Takuya\LEClientDNS01\Delegators;

use Takuya\LEClientDNS01\Acme\Resources\AcmeAuthorizationChallenge;
use Takuya\LEClientDNS01\Acme\Http\Rs256JwsSigner;
use function Takuya\Utils\base64_url_encode;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\AcmeChallengeTypeEnum;
use Takuya\LEClientDNS01\Acme\Resources\AcmeAuthorization;

class AcmeDNSChallenge {
  
  protected AcmeChallengeTypeEnum $type = AcmeChallengeTypeEnum::DNS01;
  
  protected string $dnsValue;
  
  public function __construct( protected string $domain_name,AcmeAuthorization $acmeAuthorization, AcmeAccount $account) {
    //$this->domain_name = $domain_name;
    //$this->body = $acmeAuthorization;
    //$this->account = $account;
    $this->dnsValue= $this->signDnsValue($acmeAuthorization, $account);

  }
  protected function signDnsValue(AcmeAuthorization $acmeAuthorization, AcmeAccount $account){
    $thumbprint = base64_url_encode( hash( 'sha256', Rs256JwsSigner::JwkString( $account->private_key_pem() ), true ) );
    $keyAuthorization = $acmeAuthorization->getChallenge($this->type)->getAuthToken().'.'.$thumbprint;
    $dnsValue = base64_url_encode( hash( 'sha256', $keyAuthorization, true ) );
    //
    //return [$dnsValue, $keyAuthorization,$thumbprint];
    return $dnsValue;
  }
  public function getDomainName():string{
    return $this->domain_name;
  }
  
  public function getDnsValue(): string {
    //$thumbprint = base64_url_encode( hash( 'sha256', Rs256JwsSigner::JwkString( $this->account->private_key_pem() ), true ) );
    //$keyAuthorization = $this->body->getChallenge($this->type)->getAuthToken().'.'.$thumbprint;
    //$dnsValue = base64_url_encode( hash( 'sha256', $keyAuthorization, true ) );
    return $this->dnsValue;
  }
}