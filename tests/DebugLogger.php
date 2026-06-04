<?php

namespace tests;


class DebugLogger {
  /**
   * @var resource
   */
  protected $out;
  
  /**
   * @param resource|null $file
   *
   */
  public function __construct( $file=null) {
    $this->out = match(true){
      is_resource($file) => $file,
      is_string($file) => fopen($file,'a+'),
      is_null($file) => fopen("php://memory", 'w+'),
      default => throw new \InvalidArgumentException('$file is not writable')
    };
  }
  public function getLog():string {
    rewind($this->out);
    return stream_get_contents($this->out);
  }
  public function log(string $str ) {
    fwrite($this->out,sprintf("%s\n", trim($str)));
  }
  public function debug(string $str) {
    $this->log(trim($str));
  }
}