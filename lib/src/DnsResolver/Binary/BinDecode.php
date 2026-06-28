<?php

namespace Takuya\LEClientDNS01\DnsResolver\Binary;

class BinDecode {
  public static function uint32(string $bin_str):int{
    if (strlen($bin_str)!=4) throw new \InvalidArgumentException('must be 4 byte.');
    return unpack('N',$bin_str)[1];
  }
  public static function uint16(string $bin_str):int{
    if (strlen($bin_str)!=2) throw new \InvalidArgumentException('must be 2 byte.');
    return unpack('n',$bin_str)[1];
  }
  public static function uint8( string $bin_str):int {
    if (strlen($bin_str)!=1) throw new \InvalidArgumentException('must be 1 byte.');
    return unpack('C', $bin_str)[1];
  }
  public static function read_uchar( string $binary_string, int $offset=0):string{
    if ($offset>strlen($binary_string)) throw new \InvalidArgumentException('offset is out of boundary');
    return $binary_string[$offset];
  }
  public static function read_string( string $binary_string, int $offset=0,int $len=null):string{
    $len = $len ?? strlen($binary_string)-$offset;
    if ($offset>strlen($binary_string)) throw new \InvalidArgumentException('offset is out of boundary');
    if ($offset+$len>strlen($binary_string)) throw new \InvalidArgumentException('end of string is out of boundary');
    return substr($binary_string,$offset,$len);
  }
  public static function read_uint8(string $binary_string ,int $offset=0 ):int {
    if ($offset>strlen($binary_string)) throw new \InvalidArgumentException('offset is out of boundary');
    return static::uint8( substr($binary_string,$offset,1));
  }
  public static function read_uint16(string $binary_string ,int $offset=0 ):int {
    if ($offset>strlen($binary_string)) throw new \InvalidArgumentException('offset is out of boundary');
    return static::uint16( substr($binary_string,$offset,2));
  }
  public static function read_uint32(string $binary_string ,int $offset=0 ):int {
    if ($offset>strlen($binary_string)) throw new \InvalidArgumentException('offset is out of boundary');
    return static::uint32( substr($binary_string,$offset,4));
  }
  
}