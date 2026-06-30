<?php

namespace tests\Features\DNS;

use tests\Features\CertTestCase;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\Delegators\CloudflareDNSRecord;
use function Takuya\Utils\sub_domain;

class CloudflarePluginTest extends CertTestCase {

  public function test_add_remove_txt_record(){
    $pair1 =[$this->base_domain1, $this->cf_api_token1];
    $pair2 =[$this->base_domain2, $this->cf_api_token2];
    //
    [$zone_domain,$token] = $pair1;
    $cf = new CloudflareDNSPlugin($token,$zone_domain);
    //
    [$name,$content] = [
      sprintf("%s.php-le-test.{$zone_domain}",RandomString::gen( 5, RandomString::LOWER )),
      sprintf("sample-api-%s",RandomString::gen( 15, RandomString::ALPHA )),
    ];
    $this->assertFalse($cf->isExists($name));
    // add.
    $cf->addDnsTxtRecord($name,$content);
    //
    if ($cf->canResolveDirectly()){
      $cf->waitTxtUpdated($name,$content);
      $this->assertEquals($content,$cf->query($name,'txt'));
    }
    // remove.
    $cf->removeTxtRecord($name,$content);
    // assert removed.
    $this->assertFalse($cf->isExists(sub_domain($name)));
    
  }
}