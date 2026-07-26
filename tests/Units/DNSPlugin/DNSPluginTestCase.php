<?php

namespace tests\Units\DNSPlugin;

use tests\TestCase;
use Takuya\RandomString\RandomString;

class DNSPluginTestCase extends TestCase {
  protected string $base_domain;
  protected array $domain_names;
  protected string $api_token;
  protected object $api_client;
  protected array $sample_txt ;
  
  protected function setUp(): void {
    parent::setUp();
    $this->base_domain = getenv( 'LE_BASE_DOMAIN1' );
    $this->api_token = getenv( 'LE_CLOUDFLARE_TOKEN1' );
    $sub_domain = RandomString::gen( 4, RandomString::LOWER ).'-phpunit';
    $this->domain_names = ["a.{$sub_domain}.{$this->base_domain}", "b.{$sub_domain}.{$this->base_domain}"];
    $this->sample_txt = [RandomString::gen(128),RandomString::gen(128)];
  }
  
}