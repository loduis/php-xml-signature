<?php

declare(strict_types=1);

namespace XML\Signature;

use DOMNode;
use DOMDocument;
use DOMElement;
use XML\Signature;

abstract class Validator
{
    abstract public static function verify(string $xml): bool;

    protected static function toDocument(string $xml): DOMDocument
    {
        $doc = new DOMDocument();
        $doc->preserveWhiteSpace = true;
        $doc->formatOutput = false;
        $doc->loadXML($xml);

        return $doc;
    }

    protected static function verifySignature($node)
    {
        if (!($publicKey = static::findElement($node, 'X509Certificate'))) {
            return false;
        }
        if (!($signature = static::findElement($node, 'SignatureValue'))) {
            return false;
        }

        if (!($method = static::getMethod($node, 'SignatureMethod'))) {
            return false;
        }

        if (!($info = static::findElement($node, 'SignedInfo'))) {
            return false;
        }

        $res = openssl_verify(
            $info->C14N(),
            base64_decode($signature->nodeValue),
            static::getPublicKey($publicKey),
            $method
        );

        return $res ? $info : false;
    }

    protected static function verifyReferences(DOMNode $root, DOMElement $sigInfo): bool
    {
        $_uri = '#' . ($root->getAttribute('id') ?: $root->getAttribute('Id'));
        $info = $root->C14N();
        $info = preg_replace([
            '|<ds:Signature[^>]+>.+</ds:Signature>|ms'
        ], '', $info);
        $references = $sigInfo->getElementsByTagNameNS(Signature::NS, 'Reference');
        foreach ($references as $reference) {
            $uri = $reference->getAttribute('URI');
            if ($uri != $_uri) {
                continue;
            }
            if (!($algo = static::getMethod($reference, 'DigestMethod'))) {
                return false;
            }
            if (!($value = static::findElement($reference, 'DigestValue'))) {
                return false;
            }
            if (Digest::calculate($algo, $info) === $value->nodeValue) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param DOMNode $node
     * @param string $tag
     *
     * @return string|null
     */
    private static function getMethod(DOMNode $node, string $tag)
    {
        if (!($method = static::findElement($node, $tag))) {
            return null;
        }

        return $method->getAttribute('Algorithm');
    }

    /**
     * @param mixed $doc
     * @param string $tag
     * @param string|null $ns
     *
     * @return DOMElement|null
     */
    private static function findElement($doc, string $tag, ?string $ns = null): ?DOMElement
    {
        $node = $ns ?
            $doc->getElementsByTagNameNS($ns, $tag) :
            $doc->getElementsByTagName($tag);

        if (!$node->length) {
            return null;
        }

        return $node[0];
    }

    /**
     * @param DOMNode $node
     *
     * @return resource|string
     */
    private static function getPublicKey(DOMNode $node)
    {
        $publicKey = $node->nodeValue;

        if (strpos($publicKey, "\n") === false) {
            $publicKey = chunk_split($publicKey, 64, PHP_EOL);
        } else {
            $parts = array_map(
                fn($line) => strlen($line),
                explode("\n", $publicKey)
            );
            if (max($parts) > 64) {
                $publicKey = str_replace(["\r", "\n"], "", $publicKey);
                $publicKey = chunk_split($publicKey, 64, PHP_EOL);
            }
        }
        $publicKey =
            '-----BEGIN CERTIFICATE-----' . PHP_EOL .
            $publicKey .
            '-----END CERTIFICATE-----' . PHP_EOL;

        return openssl_get_publickey($publicKey);
    }
}