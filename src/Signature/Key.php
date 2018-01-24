<?php

namespace XML\Signature;

use DomainException;
use RuntimeException;

class Key
{
    const TRIPLEDES_CBC = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';

    const AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';

    const AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';

    const AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';

    const RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';

    const RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

    const DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';

    const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

    const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';

    const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

    const HMAC_SHA1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';

    const OPTIONS = [
        self::TRIPLEDES_CBC => [
            'library'   => 'openssl',
            'cipher'    => 'des-ede3-cbc',
            'type'      => 'symmetric',
            'keysize'   => 24,
            'blocksize' => 8
        ],
        self::AES128_CBC => [
            'library'    => 'openssl',
            'cipher'    => 'aes-128-cbc',
            'type'      => 'symmetric',
            'keysize'   => 16,
            'blocksize' => 16,
        ],
        self::AES192_CBC => [
            'library'   => 'openssl',
            'cipher'    => 'aes-192-cbc',
            'type'      => 'symmetric',
            'keysize'   => 24,
            'blocksize' => 16,
        ],
        self::AES256_CBC => [
            'library'   => 'openssl',
            'cipher'    => 'aes-256-cbc',
            'type'      => 'symmetric',
            'keysize'   => 32,
            'blocksize' => 16,
        ],
        self::RSA_1_5 => [
            'library' => 'openssl',
            'padding' => OPENSSL_PKCS1_PADDING
        ],
        self::RSA_OAEP_MGF1P => [
            'library' => 'openssl',
            'padding' => OPENSSL_PKCS1_OAEP_PADDING,
            'hash'    => null
        ],
        self::RSA_SHA1 => [
            'library' => 'openssl',
            'padding' => OPENSSL_PKCS1_PADDING
        ],
        self::RSA_SHA256 => [
            'library' => 'openssl',
            'padding' => OPENSSL_PKCS1_PADDING,
            'digest'  => OPENSSL_ALGO_SHA256
        ],
        self::RSA_SHA384 => [
            'library' => 'openssl',
            'padding' => OPENSSL_PKCS1_PADDING,
            'digest'  => OPENSSL_ALGO_SHA384,
        ],
        self::RSA_SHA512 => [
            'library' => 'openssl',
            'padding' => OPENSSL_PKCS1_PADDING,
            'digest'  => OPENSSL_ALGO_SHA512,
        ],
        self::HMAC_SHA1 => [
            'library' => 'hmac',
            'digest' => 'sha1'
        ]
    ];

    protected $value;

    protected $options;

    public function __construct($value, $type, $options = ['type' => 'private'])
    {
        $params = static::OPTIONS[$type] ?? null;
        if (!$options) {
            throw new DomainException('Invalid Key Type');
        }
        if ( in_array($type, [
            static::RSA_1_5,
            static::RSA_OAEP_MGF1P,
            static::RSA_SHA1,
            static::RSA_SHA256,
            static::RSA_SHA384,
            static::RSA_SHA512
        ])) {
            if ($options &&
                ($options['type'] ?? false) &&
                !($options['type'] == 'public' || $options['type'] == 'private')
            ) {
                throw new DomainException(
                    'Certificate "type" (private/public) must be passed via parameters'
                );
            }
            $params['type'] = $options['type'];
        }
        if ($params['library'] === 'openssl' && is_string($value)) {
            $value = static::read($options['type'], $value);
        }
        $this->value = $value;
        $this->options = $params;
    }

    public static function fromFile($filename, $type = null, $options = ['type' => 'private'])
    {
        $content = file_get_contents($filename);
        $key = static::read($options['type'], $content);

        return new static ($key, $type, $options);
    }

    public static function load($content)
    {
        $keys = [];
        foreach (['private', 'public'] as $type) {
            $keys[$type] = static::read($type, $content);
        }

        return $keys;
    }

    public static function read($type, $content)
    {
        return call_user_func("openssl_get_{$type}key", $content);
    }

    public function sign($data)
    {
        return $this->{$this->options['library'] . 'Sign'}($data);
    }

    public function verify($data, $signature)
    {
        return $this->{$this->options['library'] . 'Verify'}($data, $signature) === 1;
    }

    protected function opensslSign($data)
    {
        $algo = $this->opensslAlghoritm();
        if (! openssl_sign($data, $signature, $this->value, $algo)) {
            throw new RuntimeException(
                'Failure Signing Data: ' .
                openssl_error_string() . ' - ' .
                $algo
            );
        }

        return $signature;
    }

    protected function hmacSign($data)
    {
        return hash_hmac($this->options['digest'], $data, $this->value, true);
    }

    protected function opensslVerify($data, $signature)
    {
        $algo = $this->opensslAlghoritm();

        return openssl_verify($data, $signature, $this->value, $algo);
    }

    protected function hmacVerify($data, $signature)
    {
        $expectedSignature = hash_hmac(
            $this->options['digest'],
            $data,
            $this->value,
            true
        );

        return $signature == $expectedSignature;
    }

    protected function opensslAlghoritm()
    {
        return $this->options['digest'] ?? OPENSSL_ALGO_SHA1;
    }

    public function __destruct()
    {
        openssl_free_key($this->value);
    }
}
