<?php

namespace tests;
use PHPUnit\Framework\TestCase as BaseTestCase;
use tests\assertions\AssertException;

class TestCase extends BaseTestCase {
  use AssertException;
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