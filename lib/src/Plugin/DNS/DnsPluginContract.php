<?php

namespace Takuya\LEClientDNS01\Plugin\DNS;

interface DnsPluginContract {
  public function addDnsTxtRecord ( $domain, $content ): bool;
  
  public function removeTxtRecord ( $domain, $content ): bool;
  
  public function waitTxtUpdated ( $name, $content, callable $on_wait = null );
}