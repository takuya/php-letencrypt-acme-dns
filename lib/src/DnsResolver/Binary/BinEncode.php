<?php

namespace Takuya\LEClientDNS01\DnsResolver\Binary;

class BinEncode {
  public static function uint32( int $num ): string {
    return pack( 'N', $num );
  }
  
  public static function uint16( int $num ): string {
    return pack( 'n', $num );
  }
  
  public static function uint8( int $num ): string {
    return pack( 'C', $num );
  }
  
  public static function write_uint32( &$bin_string, $offset, $val ) {
    $bin_string = substr_replace( $bin_string, static::uint32( $val ), $offset, 4 );
  }
  
  public static function write_uint16( &$bin_string, $offset, $val ) {
    $bin_string = substr_replace( $bin_string, static::uint16( $val ), $offset, 2 );
  }
  
  public static function write_uint8( &$bin_string, $offset, $val ) {
    $bin_string = substr_replace( $bin_string, static::uint8( $val ), $offset, 1 );
  }
  
  public static function write_chars( &$bin_string, $offset, string $chars ) {
    $bin_string = substr_replace( $bin_string, $chars, $offset, strlen( $chars ) );
  }
  public static function buffer($buff_size=512) {
    return str_repeat("\x00",$buff_size);
  
  }
}