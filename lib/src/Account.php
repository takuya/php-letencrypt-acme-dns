<?php

namespace Takuya\LEClientDNS01;

use Takuya\LEClientDNS01\PKey\AsymmetricKey;

class Account {
  public function __construct (
    public ?array  $key,
    public ?array  $contact,
    public ?string $initialIp,
    public ?string $createdAt,
    public ?string $status,
    public ?string $private_key = null,
  ) {
  }
  
  public static function load($file){
    $info = json_decode(file_get_contents($file),JSON_OBJECT_AS_ARRAY);
    return new static(...$info);
  }
  public static function create ( $email = '' ) {
    return new static(
      key: null,
      contact: [$email],
      initialIp: null,
      createdAt: null,
      status: null,
      private_key: ( new AsymmetricKey() )->privKey()
    );
  }
  
  
  public function toJson (): string {
    return json_encode( (array)$this, 2496 );
  }
  
  public function save ( $file ): bool {
    return file_put_contents( $file, $this->toJson() );
  }
  
  /**
   * @return string|null
   */
  public function getPrivateKey (): ?string {
    return $this->private_key;
  }
  
  /**
   * @param string|null $private_key
   */
  public function setPrivateKey ( ?string $private_key ): void {
    $this->private_key = $private_key;
  }
}