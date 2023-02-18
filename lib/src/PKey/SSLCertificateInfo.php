<?php

namespace Takuya\LEClientDNS01\PKey;

use AcmePhp\Ssl\PublicKey;

class SSLCertificateInfo {
  
  public string $name;
  public array $subject;
  public string $hash;
  public array $issuer;
  public int $version;
  public string $serialNumber;
  public string $serialNumberHex;
  public string $validFrom;
  public string $validTo;
  public int $validFrom_time_t;
  public int $validTo_time_t;
  public string $signatureTypeSN;
  public string $signatureTypeLN;
  public int $signatureTypeNID;
  public array $purposes;
  public array $extensions;
  
  public function __construct ( $cert ) {
    $arr = openssl_x509_parse( $cert, false );
    if ($arr==-false){
      throw new \InvalidArgumentException('not a valid cert');
    }
    $this->name = $arr["name"];
    $this->subject = $arr["subject"];
    $this->hash = $arr["hash"];
    $this->issuer = $arr["issuer"];
    $this->version = $arr["version"];
    $this->serialNumber = $arr["serialNumber"];
    $this->serialNumberHex = $arr["serialNumberHex"];
    $this->validFrom = $arr["validFrom"];
    $this->validTo = $arr["validTo"];
    $this->validFrom_time_t = $arr["validFrom_time_t"];
    $this->validTo_time_t = $arr["validTo_time_t"];
    $this->signatureTypeSN = $arr["signatureTypeSN"];
    $this->signatureTypeLN = $arr["signatureTypeLN"];
    $this->signatureTypeNID = $arr["signatureTypeNID"];
    $this->purposes = $arr["purposes"];
    $this->extensions = $arr["extensions"];
  }
}