<?php

namespace Takuya\LEClientDNS01\Delegators;

use Takuya\LEClientDNS01\Acme\Resources\AcmeAuthorizationChallenge;
use Takuya\LEClientDNS01\Acme\Http\Rs256JwsSigner;
use function Takuya\Utils\base64_url_encode;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\AcmeChallengeTypeEnum;
use Takuya\LEClientDNS01\Acme\Resources\AcmeAuthorization;
use function Takuya\Utils\is_wildcard_domain;
use function Takuya\Utils\parent_domain;

class AcmeDNSChallengeValue {
  const ACME_PREFIX = "_acme-challenge";
  protected AcmeChallengeTypeEnum $type = AcmeChallengeTypeEnum::DNS01;
  protected string $dnsType = 'TXT';
  
  protected string $dnsValue;
  
  public function __construct( protected string $identifier, AcmeAuthorization $acmeAuthorization,
                               AcmeAccount      $account ) {
    $this->dnsValue = $this->getSignedValue( $acmeAuthorization, $account );
  }
  
  protected function getSignedValue( AcmeAuthorization $acmeAuthorization, AcmeAccount $account ): string {
    $thumbprint = base64_url_encode( hash( 'sha256', Rs256JwsSigner::JwkString( $account->private_key_pem() ), true ) );
    $keyAuthorization = $acmeAuthorization->getChallenge( $this->type )->getAuthToken().'.'.$thumbprint;
    $dnsValue = base64_url_encode( hash( 'sha256', $keyAuthorization, true ) );
    //
    return $dnsValue;
  }
  
  public function getChallengeDomainName(): string {
    return $this->identifier;
  }
  
  public function getType(): string {
    return $this->dnsType;
  }
  
  public function acme_dns_record(): array {
    return [$this->acme_challenge_domain_name(), $this->acme_content()];
  }
  
  public function getDnsValue(): string {
    return $this->dnsValue;
  }
  
  protected function acme_challenge_domain_name(): string {
    $name = $this->getChallengeDomainName();
    $name = is_wildcard_domain( $name ) ? parent_domain( $name ) : $name;
    return sprintf( "%s.%s", self::ACME_PREFIX, $name );
  }
  
  /**
   * alias
   */
  protected function acme_content(): string {
    return $this->getDnsValue();
  }
}