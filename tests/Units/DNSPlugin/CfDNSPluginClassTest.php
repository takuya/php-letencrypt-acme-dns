<?php

namespace tests\Units\DNSPlugin;

use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
use Takuya\LEClientDNS01\DnsCheck\DnsCheckUpdateWorker;
use tests\Units\DNSPlugin\DNSPluginTestCase;

class CfDNSPluginClassTest  extends  DNSPluginTestCase  {
  
  public function test_cf_plugin_dns_update() {
    $cf = new CloudflareDNSPlugin( $this->api_token, $this->base_domain );
    $worker = new DnsCheckUpdateWorker();
    $worker->addCheck($this->domain_names[0],'txt',null);
    $worker->addCheck($this->domain_names[1],'txt',null);
    $worker->setInterval(1);
    $worker->setTimeout(60);
    $cf->addDnsTxtRecord($this->domain_names[0],$this->sample_txt[0]);
    $cf->addDnsTxtRecord($this->domain_names[1],$this->sample_txt[1]);
    $worker->waitDnsUpdate();
  }
}