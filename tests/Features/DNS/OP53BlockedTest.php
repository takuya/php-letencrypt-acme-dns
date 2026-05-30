<?php

namespace DNS;

use function Takuya\Utils\dns_resolve;
use tests\TestCase;
use function Takuya\Utils\is_directly_resolve_allowed;

class OP53BlockedTest extends TestCase {
  public function test_outbound_port_53_is_not_blocked () {
    [$name, $type,$srv] = ['cloudflare.com', 'soa', 'albert.ns.cloudflare.com'];
    if ($not_allowed=is_directly_resolve_allowed($name,1)){
      $ret = dns_resolve($name, $type,$srv );
      $this->assertNotEmpty( $ret );
    }else{
      $this->assertFalse($not_allowed);
    }
  }
}