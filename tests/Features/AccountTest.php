<?php

use tests\Features\CertTestCase;
use Takuya\RandomString\RandomString;

class AccountTest extends CertTestCase {
  public function test_save_acme_account(){

    $tmp = tempnam(sys_get_temp_dir(),'sample');
    $str = RandomString::gen( 5, RandomString::LOWER );
    $cli = $this->getInstanceLetsEncryptAcmeDNS("admin-{$str}@{$this->base_domain}");
    $acc = $cli->getAccount();
    $ret = $acc->save($tmp);
    
    $this->assertTrue($ret);
    $this->assertEquals(json_decode($acc->toJson()),json_decode(file_get_contents($tmp)));
  }
  
}