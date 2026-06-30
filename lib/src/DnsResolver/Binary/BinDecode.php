<?php

namespace Takuya\LEClientDNS01\DnsResolver\Binary;

use MongoDB\BSON\PackedArray;

class BinDecode {
  public static function uint32( string $bin_str ): int {
    if( strlen( $bin_str ) != 4 ) throw new \InvalidArgumentException( 'must be 4 byte.' );
    return unpack( 'N', $bin_str )[1];
  }
  
  public static function uint16( string $bin_str ): int {
    if( strlen( $bin_str ) != 2 ) throw new \InvalidArgumentException( 'must be 2 byte.' );
    return unpack( 'n', $bin_str )[1];
  }
  
  public static function uint8( string $bin_str ): int {
    if( strlen( $bin_str ) != 1 ) throw new \InvalidArgumentException( 'must be 1 byte.' );
    return unpack( 'C', $bin_str )[1];
  }
  
  public static function read_uchar( string $binary_string, int $offset = 0 ): string {
    if( $offset > strlen( $binary_string ) ) throw new \InvalidArgumentException( 'offset is out of boundary' );
    return $binary_string[$offset];
  }
  
  public static function read_string( string $binary_string, int $offset = 0, int $len = null ): string {
    $len = $len ?? strlen( $binary_string ) - $offset;
    if( $offset > strlen( $binary_string ) ) throw new \InvalidArgumentException( 'offset is out of boundary' );
    if( $offset + $len > strlen( $binary_string ) ) throw new \InvalidArgumentException( 'end of string is out of boundary' );
    return substr( $binary_string, $offset, $len );
  }
  
  public static function read_uint8( string $binary_string, int $offset = 0 ): int {
    if( $offset > strlen( $binary_string ) ) throw new \InvalidArgumentException( 'offset is out of boundary' );
    return static::uint8( substr( $binary_string, $offset, 1 ) );
  }
  
  public static function read_uint16( string $binary_string, int $offset = 0 ): int {
    if( $offset > strlen( $binary_string ) ) throw new \InvalidArgumentException( 'offset is out of boundary' );
    return static::uint16( substr( $binary_string, $offset, 2 ) );
  }
  
  public static function read_uint32( string $binary_string, int $offset = 0 ): int {
    if( $offset > strlen( $binary_string ) ) throw new \InvalidArgumentException( 'offset is out of boundary' );
    return static::uint32( substr( $binary_string, $offset, 4 ) );
  }
  
  public static function hexdump( string $binary_string, int $offset = 0, ?int $len = -1, $col_size = 16,
                                         $header_on = true ) {
    $str = '';
    $len ??= -1;
    $len = $len == -1 ? strlen( $binary_string ) : $len;
    $len = $len > strlen( $binary_string ) ? strlen( $binary_string ) : $len;
    $end = $offset + $len - 1;
    $end = $end > strlen( $binary_string ) - 1 ? strlen( $binary_string ) - 1 : $end;
    $line_str = '';
    foreach ( str_split( $binary_string ) as $idx => $c ) {
      //
      $lineno = intval( $idx/$col_size );
      if( $lineno < intval( $offset/$col_size ) ) {
        continue;
      }
      if( $idx%$col_size == 0 ) {
        $str .= sprintf( "%06x: ", $idx );
        $line_str = '';
      }
      //
      $str .= $idx >= $offset ? sprintf( "%02x ", ord( $c ) ) : "   ";
      $line_str .= $idx >= $offset ? $c : ' ';
      //
      [$at_eol, $at_eos] = [$idx%$col_size == $col_size - 1, $idx == $end];
      //dump(compact('at_eol','at_eos','idx'));
      if( $at_eol || $at_eos ) {
        $str .= $at_eos ? str_repeat( "   ", $col_size - $idx%$col_size - 1 ) : "";
        $chrs = array_map( fn( $c ) => ( 0x20 <= ord( $c ) && ord( $c ) <= 0x7e ) ? $c : '.', str_split( $line_str ) );
        $str .= sprintf( '  [%s]', join( $chrs + array_fill( 0, $col_size, ' ' ) ) );
        $str .= sprintf( "\n" );
        if( $at_eos ) {
          break;
        };
      }
    }
    $header = "------\ "
      .join( '|', $a = array_map( fn( $c ) => sprintf( "%02x", $c ), range( 0, $col_size - 1 ) ) )
      ."|  [".str_repeat( "*", $col_size )."]\n";
    return ( $header_on && !empty( $str ) ? $header : '' ).$str;
    //$str = '';
    //$len = min( $len??-1, strlen( $binary_string ) - $offset );
    //$len = $len==-1 ?  strlen($binary_string)-$offset-($len+1) : $len;
    //$end = $offset+$len;
    //foreach ( str_split( $binary_string,$col_size) as $idx=> $line ) {
    //  //
    //  if ( $offset>$idx*$col_size ){
    //    continue;
    //  }
    //  $bytes = array_slice(array_map('ord',str_split($line)),0,$end-$idx*$col_size);
    //  $chrs = array_map(fn($c)=>(0x20 <=$c && $c <= 0x7e)?chr($c):'.' ,$bytes);
    //  $str .=sprintf(
    //    "%06x: ".str_repeat("%02x ",sizeof($bytes)).str_repeat('   ',$col_size-sizeof($bytes))."  [%s]\n",
    //    $idx*$col_size, ...[...$bytes, join('',$chrs+array_fill(0,$col_size,' ')) ]  );
    //  //
    //  if ( $offset+$len < ($idx+1)*$col_size ){
    //    break;
    //  }
    //}
    //$header = "------\ "
    //  .join('|',$a= array_map(fn($c)=>sprintf("%02x", $c),range(0,$col_size-1)))
    //  ."|  [".str_repeat("*",$col_size)."]\n";
    //return ($header_on && !empty($str) ?$header:'').$str;
  }
  
}