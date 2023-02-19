<?php

namespace tests\assertions;

use function Takuya\Utils\assert_ipv4_address;

trait AssertIPAddress {
  public static function assertIsIPv4 ( string $expected ): void {
    static::assertTrue(assert_ipv4_address($expected));
  }
  
}