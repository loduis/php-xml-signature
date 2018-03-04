<?php

namespace XML\Signature;

use XML\Element;
use XML\Signature;

class Digest
{
    const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';

    const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

    const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';

    const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';

    const RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';

    const ALGORITHMS = [
        self::SHA1      => 'sha1',
        self::SHA256    => 'sha256',
        self::SHA384    => 'sha384',
        self::SHA512    => 'sha512',
        self::RIPEMD160 => 'ripemd160',
    ];

    public static function importInto(Element $element, $algorithm, $data)
    {
        $element->DigestMethod([
            'Algorithm' => $algorithm
        ], Signature::NS);

        $element->DigestValue(
            static::calculate($algorithm, $data),
            Signature::NS
        );
    }

    public static function calculate($algorithm, $data)
    {
        $digest = hash(static::translateAlgoritm($algorithm), $data, true);

        return base64_encode($digest);
    }

    protected static function translateAlgoritm($algorithm)
    {
        $algorithm = static::ALGORITHMS[$algorithm] ?? null;
        if (!$algorithm) {
            throw new Exception(
                "Cannot validate digest: Unsupported Algorithm <{$algorithm}>"
            );
        }

        return $algorithm;
    }
}
