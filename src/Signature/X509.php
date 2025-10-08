<?php

namespace XML\Signature;

const EMAIL_ADDRESS = 'emailAddress';
const EMAIL_OID = '1.2.840.113549.1.9.1';
const IA5STRING = 22;

class X509
{
    public $value;

    public $privateKey;

    public $publicKey;

    protected $content;

    const BEGIN_CERT = '-----BEGIN CERTIFICATE-----';

    const END_CERT = '-----END CERTIFICATE-----';

    public function __construct($content)
    {
        foreach (Key::load($this->content = $content) as $type => $key) {
            $this->{$type . 'Key'} = $key;
        }
    }

    public function getKeys()
    {
        return [
            'private' => $this->privateKey,
            'public' => $this->publicKey
        ];
    }

    public static function fromString($value)
    {
        return new static($value);
    }

    public function modulus(string $type): ?array
    {
        $key = new Key($this->publicKey, $type, ['type' => 'public']);

        if ($type === Key::RSA_SHA1) {
            $details = $key->details();
            $rsa = $details['rsa'] ?? null;

            if (!$rsa) {
                return null;
            }

            return [
                'RSA' => [
                    'value' => base64_encode($rsa['n']),
                    'exponent' => base64_encode($rsa['e'])
                ]
            ];
        }

        return null;
    }

    public static function fromFile($filename, $password = '')
    {
        $content = file_get_contents($filename);

        if (stripos($filename, '.p12') !== false && ($pem = static::p12ToPem($content, $password))) {
            $content = $pem;
        }

        return new static($content);
    }

    /**
     * Ensures a P12 file uses modern encryption algorithms compatible with OpenSSL 3.x
     * Returns path to modern P12 file (either original if already modern, or converted)
     *
     * @param string $p12FilePath Path to P12 file
     * @param string $password Password for the P12 file
     * @param string|null $outputPath Optional output path for converted file
     * @return string|null Path to modern P12 file, or null on failure
     */
    public static function ensureModernP12($p12FilePath, $password, $outputPath = null)
    {
        $content = file_get_contents($p12FilePath);

        if ($content === false) {
            return null;
        }

        // P12 is legacy, needs conversion
        $pem = static::p12ToPem($content, $password);

        if ($pem !== null) {
            return $p12FilePath;
        }

        $pem = static::convertP12ToPemViaCommand($content, $password);

        if ($pem === null) {
            return null;
        }
        // Convert PEM back to modern P12
        $outputPath = $outputPath ?? tempnam(sys_get_temp_dir(), 'modern_p12_') . '.p12';

        if (static::pemToModernP12($pem, $password, $outputPath)) {
            return $outputPath;
        }

        return null;
    }

    /**
     * Converts PEM content to modern P12 format
     *
     * @param string $pemContent PEM content
     * @param string $password Password for the new P12 file
     * @param string $outputPath Output path for P12 file
     * @return bool Success status
     */
    private static function pemToModernP12($pemContent, $password, $outputPath)
    {
        // Parse PEM content
        preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $pemContent, $certMatches);
        preg_match('/-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----/s', $pemContent, $keyMatch);

        if (empty($certMatches[0])) {
            return false;
        }

        return static::createModernP12ViaCommand($pemContent, $password, $outputPath);
    }

    /**
     * Creates a modern P12 file using openssl command with AES encryption
     *
     * @param string $pemContent PEM content
     * @param string $password Password for P12 file
     * @param string $outputPath Output path
     * @return bool Success status
     */
    private static function createModernP12ViaCommand($pemContent, $password, $outputPath)
    {
        $tempPem = tempnam(sys_get_temp_dir(), 'pem_');

        try {
            if (file_put_contents($tempPem, $pemContent) === false) {
                return false;
            }

            // Create P12 with modern algorithms (AES-256-CBC instead of RC2-40-CBC)
            $command = sprintf(
                'openssl pkcs12 -export -in %s -out %s -passout pass:%s -certpbe AES-256-CBC -keypbe AES-256-CBC -macalg SHA256 2>/dev/null',
                escapeshellarg($tempPem),
                escapeshellarg($outputPath),
                escapeshellarg($password)
            );

            shell_exec($command);

            return file_exists($outputPath) && filesize($outputPath) > 0;
        } finally {
            if (file_exists($tempPem)) {
                @unlink($tempPem);
            }
        }
    }

    public function getValue()
    {
        $allCerts = $this->all();

        if (empty($allCerts)) {
            return null;
        }

        // Extract first certificate from content for comparison
        $firstCertContent = $allCerts[0]['content'];
        $cert = openssl_x509_read($firstCertContent);

        if ($cert === false) {
            return null;
        }

        openssl_x509_export($cert, $value);

        unset($cert);

        foreach ($allCerts as $cert) {
            if (static::chunkSplit($cert['raw']) == $value) {
                return $cert['raw'];
            }
        }

        return null;
    }

    public function all($digetMethod = 'sha1')
    {
        $certs = [];
        $isPem = strpos($this->content, static::BEGIN_CERT) !== false;
        if ($isPem) {
            $data = '';
            $chunks = explode("\n", $this->content);
            $inData = false;
            foreach ($chunks as $curData) {
                if (! $inData) {
                    if (strncmp($curData, static::BEGIN_CERT, 27) == 0) {
                        $inData = true;
                    }
                } else {
                    if (strncmp($curData, static::END_CERT, 25) == 0) {
                        $inData = false;
                        $data = $this->parse($data, $digetMethod);
                        if ($data) {
                            $certs[] = $data;
                        }
                        $data = '';
                        continue;
                    }
                    $data .= trim($curData);
                }
            }
        } else {
            $cert = $this->parse($this->content, $digetMethod);
            if ($cert) {
                $certs[] = $cert;
            }
        }

        return $certs;
    }

    protected function parse($certicate, $method)
    {
        $content = $this->chunkSplit($certicate);

        if ($data = openssl_x509_parse($content)) {
            if (!empty($data['issuer']) && !empty($data['serialNumber'])) {
                if (is_array($data['issuer'])) {
                    $parts = [];
                    foreach ($data['issuer'] as $key => $value) {
                        if ($key === EMAIL_ADDRESS) {
                            $key = EMAIL_OID;
                            $value = '#' . ia5SstringToHex($value);
                        }
                        array_unshift($parts, "$key=$value");
                    }
                    $issuerName = implode(',', $parts);
                } else {
                    $issuerName = $data['issuer'];
                }

                return [
                    'raw' => $certicate,
                    'content' => $content,
                    'digest_value' => $this->digestValue($method, $content),
                    'issuer_name' => $issuerName,
                    'serial_number' => $data['serialNumber'],
                    'expired_at' => $data['validTo_time_t']
                ];
            }
        }
    }

    public static function chunkSplit($certificate)
    {
        return static::BEGIN_CERT . "\n" .
            chunk_split($certificate, 64, "\n") .
            static::END_CERT . "\n";
    }

    protected function digestValue($method, $content)
    {
        $cert = openssl_x509_read($content);
        $digestValue = openssl_x509_fingerprint($cert, $method, true);

        unset($cert);

        return base64_encode($digestValue);
    }

    protected static function p12ToPem($content, $password): ?string
    {
        // Try native PHP function first
        if (openssl_pkcs12_read($content, $certs, $password)) {
            return static::buildPemFromCerts($certs);
        }

        return null;
    }

    protected static function buildPemFromCerts($certs)
    {
        $content = [$certs['pkey'], $certs['cert']];
        if (($certs['extracerts'] ?? false) && is_array($certs['extracerts'])) {
            foreach ($certs['extracerts'] as $cert) {
                $content[] = $cert;
            }
        }
        return implode(PHP_EOL, $content);
    }

    protected static function isOpenSSLCommandAvailable()
    {
        static $available = null;

        if ($available === null) {
            // Check if shell_exec is disabled
            $disabled = explode(',', ini_get('disable_functions'));
            $disabled = array_map('trim', $disabled);

            if (in_array('shell_exec', $disabled) || !function_exists('shell_exec')) {
                $available = false;
            } else {
                // Check if openssl command exists
                $result = shell_exec('which openssl 2>/dev/null');
                $available = !empty($result);
            }
        }

        return $available;
    }

    private static function convertP12ToPemViaCommand($content, $password)
    {
        $tempP12 = tempnam(sys_get_temp_dir(), 'p12_');

        try {
            if (file_put_contents($tempP12, $content) === false) {
                return null;
            }

            // Try with -legacy flag for OpenSSL 3.x, fallback to standard for OpenSSL 1.x
            // Use -nodes to avoid encrypting the private key in output
            $command = sprintf(
                'openssl pkcs12 -in %s -passin pass:%s -nodes -legacy 2>/dev/null || openssl pkcs12 -in %s -passin pass:%s -nodes 2>/dev/null',
                escapeshellarg($tempP12),
                escapeshellarg($password),
                escapeshellarg($tempP12),
                escapeshellarg($password)
            );

            $pem = shell_exec($command);

            // Verify PEM content is valid
            if ($pem && strpos($pem, '-----BEGIN') !== false) {
                return $pem;
            }

            return null;
        } finally {
            if (file_exists($tempP12)) {
                @unlink($tempP12);
            }
        }
    }
}

function ia5SstringToHex($value) {
    $len = strlen($value);
    if ($len > 127) {
        throw new \LengthException('No se puede procesar el valor: ' . $value);
    }
    $bytes = chr(IA5STRING) . chr($len & 0x7F) . $value;
    $res = '';
    $len += 2; // sumamos los dos bytes del header
    for ($i = 0; $i < $len; ++$i) {
        $b = $bytes[$i];
        $b = ord($b);
        if($b < 16) {
            $res += '0';
        }
        $res .= dechex($b);
    }
    return $res;
}
