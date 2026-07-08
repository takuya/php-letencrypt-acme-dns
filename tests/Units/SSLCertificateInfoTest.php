<?php

namespace tests\Units;

use tests\TestCase;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;
use tests\assertions\AssertCertificate;
use function Takuya\Utils\get_certificate;

class SSLCertificateInfoTest extends TestCase {
  use AssertCertificate;
  public function test_cert_info_class(){
    $x509 = get_certificate('google.com');
    $this->assertIsCert($x509);
    $info = new SSLCertificateInfo($x509);
    $this->assertStringContainsString("Google", $info->issuer['organizationName']);
    $this->assertStringContainsString('google', $info->subject['commonName']);
    //  assert raise Exception.
    $this->assertGotException(fn()=>new SSLCertificateInfo(''),\InvalidArgumentException::class);
    $this->assertGotException(fn()=>new SSLCertificateInfo('   '),\InvalidArgumentException::class);
  }
  
}