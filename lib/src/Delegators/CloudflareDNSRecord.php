<?php

namespace Takuya\LEClientDNS01\Delegators;

class CloudflareDNSRecord {
  protected string $zone_id;
  protected \Cloudflare\API\Endpoints\DNS $cli;
  
  public function __construct ( $api_token, $name ) {
    $zone_name = base_domain( $name );
    $token = new \Cloudflare\API\Auth\APIToken( $api_token );
    $adapter = new \Cloudflare\API\Adapter\Guzzle( $token );
    $zone = new \Cloudflare\API\Endpoints\Zones( $adapter );
    $zone_id = $zone->getZoneID( $zone_name );
    $dns = new \Cloudflare\API\Endpoints\DNS( $adapter );
    $this->zone_id = $zone_id;
    $this->cli = $dns;
  }
  
  public function isExists ( $name, $type,$content=null ): bool {
    return sizeof( $this->findRecordIds( $name, $type,$content ) ) > 0;
  }
  
  public function findRecordIds ( $name, $type, $content=null ): array {
    $q = [
      'zoneID' => $this->zoneID(),
      'type' => $type,
      'name' => $name,
      'content'=>$content,
    ];
    $q = array_filter($q);
    $ret = $this->cli->listRecords( ...$q );
    $ret = array_map( function( $e ) { return (string)$e->id; }, $ret->result );
    return array_filter( $ret );
  }
  
  public function zoneID (): string {
    return $this->zone_id;
  }
  
  public function deleteRecord ( $record_id ): bool {
    return $this->cli->deleteRecord( ...['zoneID' => $this->zoneID(), 'recordID' => $record_id] );
  }
  
  public function getRecordId ( $name, $type, $content=null ) {
    $ret = $this->findRecordIds( $name, $type, $content );
    return !empty( $ret ) ? $ret[0] : null;
  }
  
  public function addRecord ( $type, $name, $content, $proxied = false ) {
    $param = [
      'zoneID' => $this->zoneID(),
      'type' => $type,
      'name' => $name,
      'content' => $content,
      'proxied' => $proxied,
    ];
    $result = $this->cli->addRecord( ...$param );
    return $result;
  }
  
}