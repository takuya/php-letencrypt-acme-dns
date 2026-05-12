<?php

require_once __DIR__.DIRECTORY_SEPARATOR.'../vendor/autoload.php';

use Takuya\LEClientDNS01\Delegators\CloudflareDNSRecord;

function load_env() {
  $obj = (object)[];
  $env_keys = [
    'base_domain' => 'LE_BASE_DOMAIN1',
    'cf_api_token' => 'LE_CLOUDFLARE_TOKEN1',
    //
    'base_domain1' => 'LE_BASE_DOMAIN1',
    'cf_api_token1' => 'LE_CLOUDFLARE_TOKEN1',
    //
    'base_domain2' => 'LE_BASE_DOMAIN2',
    'cf_api_token2' => 'LE_CLOUDFLARE_TOKEN2',
    'email' => 'LE_SAMPLE_EMAIL',
  ];
  foreach ( $env_keys as $name => $env_key ) {
    $obj->{$name} = getenv( $env_key );
  }
  return $obj;
}
function remove_junk($api_token,$zone_domain){
  $method = new ReflectionMethod(CloudflareDNSRecord::class,'cf_factory');
  /** @var \Cloudflare\API\Endpoints\DNS $cf_cli */
  [$zone_id,$cf_cli] = $method->invokeArgs(null,[$api_token,$zone_domain]);
  $ret = $cf_cli->listRecords($zone_id,"TXT")?->result;
  $junk_items = [];
  foreach ($ret as $item){
    if (str_contains($item->name,'le-test' )||str_contains($item->name,'_acme-challenge')){
      $junk_items[] =$item;
    }
  }
  foreach ($junk_items as $item){
    echo "{$junk_items->name}";
    $cf_cli->deleteRecord($zone_id,$item->id);
    echo "deleted".PHP_EOL;
  }
}

function main(){
  $env = load_env();
  $pair1 =[ $env->cf_api_token1,$env->base_domain1,];
  $pair2 =[ $env->cf_api_token2,$env->base_domain2,];
  remove_junk(...$pair1);
  remove_junk(...$pair2);
}
if (realpath($argv[0]) === realpath(__FILE__)) {
  main();
}



