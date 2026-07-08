<?php

namespace Takuya\LEClientDNS01\DnsCheck;

class ResolveConf {
  public static $path = '/etc/resolv.conf';
  public static function servers() {
    return static::parse()['servers'];
  }
  public static function parse():array {
    $s = file_get_contents(static::$path);
    preg_match_all(
      '/^(?P<key>nameserver|search|domain|options)\s+(?P<value>.*)$/m',
      $s,
      $m,
      PREG_SET_ORDER
    );
    $result = [];
    foreach ($m as $row) {
      $result[$row['key']][] = $row['value'];
    }
    return $result;
  }
}