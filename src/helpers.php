<?php

namespace XML
{
    function str_camel($value)
    {
        $value = ucwords(str_replace(['-', '_'], ' ', $value));
        $value = str_replace(' ', '', $value);

        return lcfirst($value);
    }
}

namespace XML\Signature
{
    use XML\Signature\X509;

    function ensure_xmlns(array $namespaces): array
    {
        $res = [];
        array_walk($namespaces, function ($value, $key)  use (&$res){
            if (strpos($key, 'xmlns:') !== 0) {
                $res['xmlns:' . $key] = $value;
            }
        });

        return $res;
    }

    function x509($certificate)
    {
        if ($certificate instanceof X509) {
            return $certificate;
        }
        if (is_string($certificate)) {
            return ($path = realpath($certificate)) ?
                X509::fromFile($path) :
                X509::fromString($certificate);
        }
        if (is_iterable($certificate) && ($certificate['filename'] ?? false)) {
            ['filename' => $filename, 'password' => $password] = $certificate;
            return X509::fromFile(realpath($filename), $password);
        }

        return $certificate;
    }
}
