<?php

namespace tests\assertions;

trait AssertException {
  public function assertGotException( callable $func, string $exception): void {
    $gotException = null;
    try {
      $func();
    }catch (\Exception $e){
      $gotException = get_class($e);
    }
    $this->assertEquals($exception,$gotException);
  }
  public function assertNotGotException( callable $func): void {
    $gotException = null;
    try {
      $func();
    }catch (\Exception $e){
      $gotException = get_class($e);
    }
    $this->assertNull($gotException);
  }
  
}