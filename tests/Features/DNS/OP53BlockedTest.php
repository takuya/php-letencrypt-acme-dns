<?php

namespace DNS;

use function Takuya\Utils\dns_resolve;
use tests\TestCase;

class OP53BlockedTest extends TestCase {
  public function test_outbound_port_53_is_not_blocked () {
    $ret = dns_resolve( 'cloudflare.com', 'soa', 'albert.ns.cloudflare.com' );
    $this->assertNotEmpty( $ret );
  }
}