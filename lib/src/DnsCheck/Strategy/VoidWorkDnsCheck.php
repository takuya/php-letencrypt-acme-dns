<?php

namespace Takuya\LEClientDNS01\DnsCheck\Strategy;


use function Takuya\Utils\dns_resolve;

class VoidWorkDnsCheck extends DnsUpdateCheck {
  protected function resolve(): array {
    return ['domain' => $this->domain_name, 'type' => null, 'time' => null];
  }
  public function isChanged(): bool {
    return false;
  }
}