<?php

namespace XML\Signature;

class X509
{
    public $value;

    public $privateKey;

    public $publicKey;

    const BEGIN_CERT = '-----BEGIN CERTIFICATE-----';

    const END_CERT = '-----END CERTIFICATE-----';

    public function __construct($content)
    {
        $cert = openssl_x509_read($content);
        openssl_x509_export($cert, $this->value);

        foreach (Key::load($content) as $type => $key) {
            $this->{$type . 'Key'} = $key;
        }

        openssl_x509_free($cert);
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

    public static function fromFile($filename)
    {
        return new static(file_get_contents($filename));
    }

    public function all()
    {
        $certs = [];
        $isPem = strpos($this->value, static::BEGIN_CERT) !== false;
        if ($isPem) {
            $data = '';
            $chunks = explode("\n", $this->value);
            $inData = false;
            foreach ($chunks AS $curData) {
                if (! $inData) {
                    if (strncmp($curData, static::BEGIN_CERT, 27) == 0) {
                        $inData = true;
                    }
                } else {
                    if (strncmp($curData, static::END_CERT, 25) == 0) {
                        $inData = false;
                        $data = $this->parse($data);
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
            $cert = $this->parse($this->value);
            if ($cert) {
                $certs[] = $cert;
            }
        }

        return $certs;
    }

    protected function parse($certicate)
    {
        $content = static::BEGIN_CERT . "\n" .
            chunk_split($certicate, 64, "\n") .
            static::END_CERT . "\n";
        if ($data = openssl_x509_parse($content)) {
            if (!empty($data['issuer']) && !empty($data['serialNumber'])) {
                if (is_array($data['issuer'])) {
                    $parts = array();
                    foreach ($data['issuer'] AS $key => $value) {
                        array_unshift($parts, "$key=$value");
                    }
                    $issuerName = implode(',', $parts);
                } else {
                    $issuerName = $data['issuer'];
                }
                return [
                    'raw' => $certicate,
                    'issuer_name' => $issuerName,
                    'serial_number' => $data['serialNumber']
                ];
            }
        }
    }
}
