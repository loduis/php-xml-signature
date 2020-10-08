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

    public static function fromFile($filename, $password = '')
    {
        $content = file_get_contents($filename);

        if (stripos($filename, '.p12') !== false && ($pem = static::p12ToPem($content, $password))) {
            $content = $pem;
        }

        return new static($content);
    }

    public function getValue()
    {
        $cert = openssl_x509_read($this->content);

        openssl_x509_export($cert, $value);

        openssl_x509_free($cert);

        foreach ($this->all() as $cert) {
            if ($this->chunkSplit($cert['raw']) == $value) {
                return $cert['raw'];
            }
        }
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

    protected function chunkSplit($certicate)
    {
        return static::BEGIN_CERT . "\n" .
            chunk_split($certicate, 64, "\n") .
            static::END_CERT . "\n";
    }

    protected function digestValue($method, $content)
    {
        $cert = openssl_x509_read($content);
        $digetValue = openssl_x509_fingerprint($cert, $method, true);
        openssl_x509_free($cert);

        return base64_encode($digetValue);
    }

    protected static function p12ToPem($content, $password)
    {
        if (openssl_pkcs12_read($content, $certs, $password)) {
            $content = [$certs['pkey'], $certs['cert']];
            if (($certs['extracerts'] ?? false) && is_array($certs['extracerts'])) {
                foreach ($certs['extracerts'] as $cert) {
                    $content[] = $cert;
                }
            }
            return implode(PHP_EOL, $content);
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
