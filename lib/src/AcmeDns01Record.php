<?php

namespace Takuya\LEClientDNS01;

use function Takuya\Utils\base64_url_encode;
use function Takuya\Utils\is_wildcard_domain;
use function Takuya\Utils\parent_domain;

class AcmeDns01Record {
  const ACME_PREFIX = "_acme-challenge";
  
  public function __construct (
    protected string $domain,
    protected        $payload
  ) {
  }
  
  public function acme_challenge_domain_name (): string {
    $name = is_wildcard_domain($this->domain) ? parent_domain($this->domain):$this->domain;
    return sprintf( "%s.%s", self::ACME_PREFIX, $name );
  }
  
  public function acme_content (): string {
    return $this->payload;
  }
  
  
}