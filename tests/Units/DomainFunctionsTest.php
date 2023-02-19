<?php
namespace tests\Units;

use tests\TestCase;
use function Takuya\Utils\assert_str_is_domain;
use function Takuya\Utils\base_domain;
use function Takuya\Utils\sub_domain;
use function Takuya\Utils\domain_ns;
use function Takuya\Utils\parent_domain;
use Takuya\RandomString\RandomString;

class DomainFunctionsTest  extends TestCase {
  public function test_function_assert_str_is_domain(){
    $this->assertTrue(assert_str_is_domain('example.tld'));
    $this->assertFalse(assert_str_is_domain('example,tld'));
    $this->assertFalse(assert_str_is_domain('*.example,tld'));
    $this->assertFalse(assert_str_is_domain(''));
  }
  public function test_function_base_domain(){
    $expected = 'example.tld';
    $this->assertEquals($expected,base_domain('example.tld'));
    $this->assertEquals($expected,base_domain('www.example.tld'));
    $this->assertEquals($expected,base_domain('*.www.example.tld'));
    $this->assertEquals($expected,base_domain('a.b.c.example.tld'));
  }
  public function test_function_parent_domain(){
    $this->assertEquals('www.example.tld',parent_domain('*.www.example.tld'));
    $this->assertEquals('example.tld',parent_domain('www.example.tld'));
    $this->assertEquals('example.tld',parent_domain('example.tld'));
    // get tld
    $this->assertEquals('tld',parent_domain('example.tld',false));
    $this->assertEquals('.',parent_domain('tld',false));
  }
  public function test_function_sub_domain(){
    $this->assertEquals('www',sub_domain('www.example.tld'));
    $this->assertEquals('a.b',sub_domain('a.b.example.tld'));
    $this->assertEquals('*',sub_domain('*.example.tld'));
  }
  public function test_function_domain_ns(){
    // root servers.
    $this->assertMatchesRegularExpression('/[a-x].root-servers.net/', domain_ns(''));
    $this->assertMatchesRegularExpression('/[a-x].root-servers.net/', domain_ns('.'));
    // search ns record.
    $this->assertMatchesRegularExpression('/ns\d+\.google\.com/', domain_ns('g.co'));
    $this->assertMatchesRegularExpression('/ns\d+\.google\.com/', domain_ns('a.g.co'));
    $this->assertMatchesRegularExpression('/ns\d+\.google\.com/', domain_ns('a.b.g.co'));
    $this->assertMatchesRegularExpression('/ns\d+\.google\.com/', domain_ns('a.b.c.g.co'));
    $this->assertMatchesRegularExpression('/ns\d+\.google\.com/', domain_ns('*.a.b.c.g.co'));
    // search unknonw
    $this->assertMatchesRegularExpression('/[a-x].gtld-servers.net/', domain_ns(".com"));
    $rand = RandomString::gen(25,RandomString::LOWER);
    $this->assertMatchesRegularExpression('/[a-x].gtld-servers.net/', domain_ns("{$rand}.com"));
    
  }
}