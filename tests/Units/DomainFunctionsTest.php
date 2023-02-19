<?php
namespace tests\Units;

use tests\TestCase;
use function Takuya\Utils\assert_str_is_domain;
use function Takuya\Utils\base_domain;
use function Takuya\Utils\sub_domain;

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
    $expected = 'example.tld';
    $this->assertEquals($expected,base_domain('www.example.tld'));
    $this->assertEquals($expected,base_domain('*.www.example.tld'));
  }
  public function test_function_sub_domain(){
    $this->assertEquals('www',sub_domain('www.example.tld'));
    $this->assertEquals('a.b',sub_domain('a.b.example.tld'));
    $this->assertEquals('*',sub_domain('*.example.tld'));
  }
  
  
}