<?php

namespace Takuya\LEClientDNS01\Delegators;

interface DnsAPIForLEClient {
  public function changeDnsTxtRecord ( $domain, $content ): bool;
  
  public function removeTxtRecord ( $domain ): bool;
  
}