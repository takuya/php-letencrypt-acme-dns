<?php

namespace Takuya\LEClientDNS01;

class AcmeDns01Record {
  const ACME_PREFIX = "_acme-challenge";
  
  public function __construct (
    protected string $domain,
    protected        $payload
  ) {
  }
  
  public function acme_domain_name () {
    return sprintf( "%s.%s", self::ACME_PREFIX, $this->domain );
  }
  
  public function acme_content () {
    return \base64_url_encode( hash( 'sha256', $this->payload, true ) );
  }
  
  
}