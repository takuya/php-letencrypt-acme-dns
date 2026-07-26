<?php

namespace Takuya\LEClientDNS01\Plugin\DNS;



abstract class DNSPlugin implements DnsPluginContract {
  
  public abstract function addDnsTxtRecord ( $domain, $content ): bool;
  
  public abstract function removeTxtRecord ( $domain, $content ): bool;
  
}