<?php

namespace Takuya\LEClientDNS01\Plugin\DNS;


use Takuya\LEClientDNS01\Plugin\DNS\traits\DNSRecordUpdateWaiting;

abstract class DNSPlugin implements DnsPluginContract {
  use DNSRecordUpdateWaiting;
  
  public abstract function addDnsTxtRecord ( $domain, $content ): bool;
  
  public abstract function removeTxtRecord ( $domain, $content ): bool;
  
}