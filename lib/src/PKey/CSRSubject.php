<?php

namespace Takuya\LEClientDNS01\PKey;

class CSRSubject {
  public function __construct (
    public string  $commonName,
    public ?string $countryName = null,
    public ?string $stateOrProvinceName = null,
    public ?string $localityName = null,
    public ?string $organizationName = null,
    public ?string $organizationalUnitName = null,
    public ?string $emailAddress = null,
    public ?array   $subjectAlternativeNames = []// openssl_csr_new will ignore this.
  ) {
  }
  
  public function toArray (): array {
    return array_filter( [
      'commonName' => $this->commonName,
      'countryName' => $this->countryName,
      'stateOrProvinceName' => $this->stateOrProvinceName,
      'localityName' => $this->localityName,
      'organizationName' => $this->organizationName,
      'organizationalUnitName' => $this->organizationalUnitName,
      'emailAddress' => $this->emailAddress,
      'subjectAlternativeNames' => $this->subjectAlternativeNames,
    ] );
  }
  
}

