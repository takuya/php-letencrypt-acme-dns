<?php

namespace Takuya\LEClientDNS01\PKey;

use Takuya\RandomString\RandomString;
use OpenSSLCertificateSigningRequest;
use function PHPUnit\Framework\isString;
use function PHPUnit\Framework\fileExists;

class CSRSubject {// ドメイン名証明書用のCSRなので、CSRではなく、 DvCsrとかにするべきかもね。EVのCSRとは根本的に異なるわけで。
  /**
   * @param string      $commonName
   * @param string|null $countryName
   * @param string|null $stateOrProvinceName
   * @param string|null $localityName
   * @param string|null $organizationName
   * @param string|null $organizationalUnitName
   * @param string|null $emailAddress
   * @param array|null  $subjectAlternativeNames SAN値が本来Subject対象外だが、まとめて扱うほうが便利なので。
   */
  public function __construct (
    public string  $commonName,
    public ?string $countryName = null,
    public ?string $stateOrProvinceName = null,
    public ?string $localityName = null,
    public ?string $organizationName = null,
    public ?string $organizationalUnitName = null,
    public ?string $emailAddress = null,
    public ?array  $subjectAlternativeNames = []// openssl_csr_new will ignore this.
  ) {
  }
  
  public function toArray (): array {
    return array_filter( [
      'commonName' => $this->commonName,
      'countryName' => $this->countryName,
      'stateOrProvinceName' => $this->stateOrProvinceName,
      'localityName' => $this->localityName,
      'organizationName' => $this->organizationName,
      'organizationalUnitName' => $this->organizationalUnitName,
      'emailAddress' => $this->emailAddress,
    ] );
  }
  protected function req_distinguished_name() {
    $str = "";
    $max = max(array_map('strlen',array_keys($this->toArray())));
    foreach($this->toArray() as $k=>$v){
      $str .= sprintf("%- {$max}s = %s\n",$k,$v);
    }
    return $str;
  }
  
  /**
   * @param \OpenSSLAsymmetricKey $pkey
   * @return string CSR as PEM.
   */
  public function getRequest( \OpenSSLAsymmetricKey $pkey):string {
    $csr = openssl_csr_new($this->toArray(),$pkey,$this->csrConfig($tmp=sys_get_temp_dir().DIRECTORY_SEPARATOR.RandomString::gen(10)));
    openssl_csr_export($csr,$csrText);
    @unlink($tmp);
    return $csrText;
  }
  public function csrConfig(string $tmp_file_path) {
    $sanString = "DNS:" . implode(",DNS:", $this->subjectAlternativeNames);
    $configContent = <<<"EOS"
      [req]
      distinguished_name = req_distinguished_name
      req_extensions = v3_req
      
      [req_distinguished_name]
      
      [v3_req]
      subjectAltName = $sanString
      EOS;
    //
    $configArgs = [
      'config' => $tmp_file_path,
      'x509_extensions' => 'v3_req',
      "digest_alg" => "sha256",
    ];
    file_put_contents($configArgs['config'], $configContent);
    return $configArgs;
  }
  public static function dumpCSR(string|\OpenSSLCertificateSigningRequest $csr) {
    if (!is_string($csr)){
      openssl_csr_export($csr,$out);
      $csr = $out;
    }
    // openssl req -text で中身をパースして文字列で受け取る
    $fd_spec = [
      0 => ["pipe", "r"],
      1 => ["pipe", "w"],
      2 => ["pipe", "w"],
    ];
    $process = proc_open("openssl req -noout -text", $fd_spec, $pipes);
    fwrite($pipes[0], $csr);
    fclose($pipes[0]);
    
    $output = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);
    return $output;
  }
}

