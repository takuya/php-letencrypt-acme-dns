<?php

namespace tests\Units;

use tests\TestCase;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;
use tests\assertions\AssertCertificate;

class SSLCertificateInfoTest extends TestCase {
  use AssertCertificate;
  public function test_cert_info_class(){
    $x509 = get_certificate('google.com');
    $this->assertIsCert($x509);
    $info = new SSLCertificateInfo($x509);
    $this->assertStringContainsString("Google", $info->issuer['organizationName']);
    $this->assertStringContainsString('google', $info->subject['commonName']);
  
    $this->expectException(\InvalidArgumentException::class);
    $info = new SSLCertificateInfo('');
  }
  
}