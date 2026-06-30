<?php

namespace Takuya\LEClientDNS01\Acme\Store;

use Takuya\LEClientDNS01\PKey\CertificateWithPrivateKey;

class AcmeCertificateStore {
  
  public static function save( string $filename,CertificateWithPrivateKey $cert ): false|int {
    return file_put_contents( $filename, json_encode( $cert->toArray(), JSON_PRETTY_PRINT ) );
  }

}