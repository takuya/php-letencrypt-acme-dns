<?php

namespace Takuya\LEClientDNS01\Acme\Resources;


class AcmeAuthorization {
  
  protected object $authorization;
  
  public function __construct(
    protected string    $domain_name,
    protected string    $url,
    protected AcmeOrder $order ) {
  }
  
  protected function challenges() {
    $this->authorization = $this->authorization ?? json_decode( file_get_contents( $this->url ) );
    return $this->authorization->challenges;
  }
  
  /**
   * @param AcmeChallengeType $type http-01,dns-01,tls-alpn-01
   * @return object|null
   */
  public function getChallenge( AcmeChallengeType $type ): object {
    $found = null;
    foreach ( $this->challenges() as $challenge ) {
      if( strcasecmp( $challenge->type, $type->value ) === 0 ) {
        $found = new AcmeAuthorizationChallenge( $challenge );
        break;
      }
    }
    return $found;
  }
  
  
}