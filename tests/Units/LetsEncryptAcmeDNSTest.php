<?php

namespace tests\Units;

use tests\TestCase;
use Takuya\LEClientDNS01\LetsEncryptAcmeDNS;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;

class LetsEncryptAcmeDNSTest extends TestCase {
  public function test_validate_domain () {
    $obj = $this->getMockObject( LetsEncryptAcmeDNS::class );
    $method = $this->getMethod( LetsEncryptAcmeDNS::class, 'validateDomainName' );
    //
    $names = ['example.com'];
    $ret = $method->invokeArgs( $obj, [$names] );
    $this->assertEquals( $ret, $names );
    //
    $names = ['*.example.com'];
    $this->assertNotGotException( function() use ( $method, $obj, $names ) {
      $ret = $method->invokeArgs( $obj, [$names] );
      $this->assertEquals( $names, $ret );
    } );
    //
    $names = ['example,com'];
    $this->assertGotException( function() use ( $method, $obj, $names ) {
      $ret = $method->invokeArgs( $obj, [$names] );
      $this->assertEquals( $names, $ret );
    }, \InvalidArgumentException::class );
  }
  
  public function test_add_get_dns_plugin () {
    $obj = $this->getMockObject( LetsEncryptAcmeDNS::class );
    $add_method = $this->getMethod( LetsEncryptAcmeDNS::class, 'setDnsPlugin' );
    $get_method = $this->getMethod( LetsEncryptAcmeDNS::class, 'getDnsPlugin' );
    $dns = $this->getMockObject( CloudflareDNSPlugin::class );
    ////
    $add_method->invokeArgs( $obj, [$dns] );
    $ret = $get_method->invokeArgs( $obj, [] );
    $this->assertSame( $ret, $dns );
    //
    $add_method->invokeArgs( $obj, [$dns] );
    $ret = $get_method->invokeArgs( $obj, ['example.com'] );
    $this->assertSame( $ret, $dns );
    //
    $add_method->invokeArgs( $obj, [$dns, 'example.com'] );
    $ret = $get_method->invokeArgs( $obj, ['example.com'] );
    $this->assertSame( $ret, $dns );
  }
  
  public function test_add_get_dns_plugin_with_domain_name () {
    $obj = $this->getMockObject( LetsEncryptAcmeDNS::class );
    $add_method = $this->getMethod( LetsEncryptAcmeDNS::class, 'setDnsPlugin' );
    $get_method = $this->getMethod( LetsEncryptAcmeDNS::class, 'getDnsPlugin' );
    $dns = $this->getMockObject( CloudflareDNSPlugin::class );
    //
    //
    $add_method->invokeArgs( $obj, [$dns, 'example.com'] );
    $ret = $get_method->invokeArgs( $obj, ['example.com'] );
    $this->assertSame( $ret, $dns );
    //
    $default_dns = $this->getMockObject( CloudflareDNSPlugin::class );
    $add_method->invokeArgs( $obj, [$default_dns] );
    $ret = $get_method->invokeArgs( $obj, ['example.com'] );
    $this->assertSame( $ret, $dns );
    $ret = $get_method->invokeArgs( $obj, [] );
    $this->assertSame( $default_dns, $ret );
    $this->assertNotSame( $dns, $ret );
  }
  
}