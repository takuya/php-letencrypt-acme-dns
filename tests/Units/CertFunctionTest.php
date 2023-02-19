<?php

namespace tests\Units;

use tests\TestCase;
use function Takuya\Utils\get_certificate;

class CertFunctionTest extends TestCase {
  public function test_get_x509_cert_from_web () {
    $ret = get_certificate( 'google.com' );
    $cert = openssl_x509_read($ret);
    $info = openssl_x509_parse($cert,false);
    $this->assertStringContainsString('google.com',$info['subject']['commonName']);
  }
  
}