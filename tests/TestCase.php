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
  
  protected function setUp (): void {
    parent::setUp();
    $env_keys = [
      'base_domain' => 'LE_BASE_DOMAIN1',
      'cf_api_token' => 'LE_CLOUDFLARE_TOKEN1',
      'base_domain1' => 'LE_BASE_DOMAIN1',
      'cf_api_token1' => 'LE_CLOUDFLARE_TOKEN2',
      'base_domain2' => 'LE_BASE_DOMAIN2',
      'cf_api_token2' => 'LE_CLOUDFLARE_TOKEN2',
      'email' => 'LE_SAMPLE_EMAIL',
    ];
    foreach ( $env_keys as $name => $env_key ) {
      $this->{$name} = getenv( $env_key );
    }
  }
  
  
}