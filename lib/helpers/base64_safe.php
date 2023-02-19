<?php

namespace Takuya\Utils;

if ( !function_exists( __NAMESPACE__ .'\base64_url_encode' ) ) {
  function base64_url_encode ( string $input ): string {
    return str_replace( '=', '', strtr( base64_encode( $input ), '+/', '-_' ) );
  }
}
if ( !function_exists( __NAMESPACE__ .'\base64_url_decode' ) ) {
  function base64_url_decode ( string $input ): bool|string {
    if ( $r = \strlen( $input ) % 4 ) {
      $input .= str_repeat( '=', 4 - $r );
    }
    return base64_decode( strtr( $input, '-_', '+/' ) );
  }
}
