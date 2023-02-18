<?php

namespace tests;
use PHPUnit\Framework\TestCase as BaseTestCase;
use tests\assertions\AssertException;

class TestCase extends BaseTestCase {
  use AssertException;
  protected string $base_domain;
  protected string $cf_api_token;
  protected string $base_domain1;
  protected string $cf_api_token1;
  protected string $base_domain2;
  protected string $cf_api_token2;
  protected string $email;
  
  protected function getMethod ( $class, $method ) {
    $class = new \ReflectionClass( $class );
    $method = $class->getMethod( $method );
    $method->setAccessible( true );
    return $method;
  }
  
  protected function getMockObject ( $class ) {
    return $this->getMockBuilder( $class )
                ->disableOriginalConstructor()
                ->getMock();
  }
  
  
}