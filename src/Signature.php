<?php

namespace XML;

use DOMNode;
use DOMXpath;
use DOMDocument;
use RuntimeException;
use XML\Signature\Key;
use XML\Signature\X509;
use XML\Signature\Xades;
use XML\Signature\Digest;
use XML\Signature\Canonicalize;

class Signature
{
    const NS = 'http://www.w3.org/2000/09/xmldsig#';

    const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    protected $id;

    protected $canonicalMethod = Canonicalize::C14N;

    protected $keyAlgorithm = Key::RSA_SHA1;

    protected $digestAlgorithm = Digest::SHA1;

    protected $xades;

    protected $privateKey;

    protected $publicKey;

    protected $certificate;

    protected $keyInfoId;

    protected $objectId;

    protected $referenceId;

    private $root;

    private $signedInfo;

    private $value;

    private $data;

    public function __construct(array $options = [])
    {
        foreach ($options as $key => $value) {
            $key = str_camel($key);
            $this->$key = $value;
        }

        if ($options['certificate'] ?? false && is_string($options['certificate'])) {
            $options['certificate'] = ($path = realpath($options['certificate'])) ?
                X509::fromFile($path) :
                X509::fromString($options['certificate']);
        }

        foreach (['private', 'public'] as $key) {
            $this->ensureKey($key);
        }

        if ($this->xades) {
            $this->xades['target'] = $this->id;
            $this->xades['algorithm'] = $this->digestAlgorithm;
            if (is_array($this->xades)) {
                $this->xades = new Xades($this->xades);
            }
            if (!($this->xades['certs'] ?? false) && $this->certificate instanceof X509) {
                $this->xades['certs'] = $this->certificate->all();
            }
        }

        $this->root = Element::create('ds:Signature', [
            'Id' => $this->id,
            'xmlns:ds' => static::NS
        ]);
    }

    public function sign(DOMNode $node, $appendTo = null)
    {
        $this->addSignedInfo($node, [
            static::ENVELOPED_SIGNATURE
        ]);
        $this->addValue();
        $this->exportTo($node, $appendTo);
    }

    public function append(DOMNode $node)
    {
        if ($node instanceof DOMDocument) {
            $node = $node->documentElement;
        }
        $document = $node->ownerDocument;
        $signature = $document->importNode($this->root->toElement(), true);
        $node->appendChild($signature);
    }

    public function verify()
    {
        if (!$this->value) {
            throw new RuntimeException('Not document signed');
        }

        return $this->publicKey->verify($this->data, $this->value);
    }

    public function __toString()
    {
        return $this->root->pretty();
    }

    protected function exportTo($node, $appendTo)
    {
        if ($appendTo instanceof DOMNode) {
            $this->append($appendTo);
        } elseif (is_callable($appendTo)) {
            $doc = $node instanceof DOMDocument ? $node : $node->ownerDocument;
            $xpath = new DOMXpath($doc);
            $node = $appendTo($xpath);
            if (is_array($node) && count($node) === 1) {
                $node = $node[0];
            }
            if ($node instanceof DOMNode) {
                $this->append($node);
            }
        } else {
            $this->append($node);
        }
    }

    protected function addReference($node, array $attributes = [], array $transforms = [])
    {
        $transforms = array_map(function ($value) {
            return is_scalar($value) ? ['Algorithm' => $value] : $value;
        }, $transforms);
        $this->signedInfo->Reference(
            $attributes,
            function ($reference) use ($transforms, $node) {
                $this->addTransforms($reference, $transforms);
                Digest::importInto(
                    $reference,
                    $this->digestAlgorithm,
                    $this->canonicalize($node)
                );
            }
        );
    }

    protected function addValue()
    {
        $signatureValue = $this->root->SignatureValue();
        if ($this->certificate) {
            $this->addKeyInfo();
            $this->addXades();
        }
        $this->data = $this->canonicalize($this->signedInfo);
        $this->value = $this->privateKey->sign($this->data);
        $signatureValue->setValue(base64_encode($this->value));
    }

    protected function addKeyInfo()
    {
        $this->root->KeyInfo(function ($keyInfo) {
            $keyInfo->X509Data(function ($X509Data) {
                foreach ($this->certificate->all() as $cert) {
                    $X509Data->X509Certificate($cert['raw']);
                }
            });
            if ($this->keyInfoId) {
                $keyInfo['Id'] = $this->keyInfoId;
                $this->addReference($keyInfo, [
                    'URI' => '#' . $this->keyInfoId
                ]);
            }
        });
    }

    protected function addXades()
    {
        if ($this->xades) {
            $this->root->Object(function ($object) {
                if ($this->objectId) {
                    $object['Id'] = $this->objectId;
                }
                $signedProperties = $this->xades->appendInto($object);
                if ($this->xades['id']) {
                    $this->addReference($signedProperties, [
                        'Type' => 'http://uri.etsi.org/01903#SignedProperties',
                        'URI' => '#' . $this->xades['id']
                    ]);
                }
            });
        }
    }

    protected function addSignedInfo($node, $transforms)
    {
        $this->root->SignedInfo(function ($signedInfo) {
            $signedInfo->CanonicalizationMethod([
                'Algorithm' => $this->canonicalMethod
            ]);
            $signedInfo->SignatureMethod([
                'Algorithm' => $this->keyAlgorithm
            ]);
            $this->signedInfo = $signedInfo;
        });

        $this->addReference($node, [
            'Id' => $this->referenceId,
            'URI' => ''
        ], $transforms);
    }

    protected function addTransforms(Element $reference, array $values)
    {
        if ($values) {
            $reference->Transforms(function ($transforms) use ($values) {
                foreach ($values as $transform) {
                    $transforms->Transform($transform);
                }
            });
        }
    }

    protected function canonicalize($node)
    {
        return (new Canonicalize($this->canonicalMethod))->node($node);
    }

    protected function ensureKey($type)
    {
        if ((!$this->{$type . 'Key'} instanceof Key) && $this->certificate instanceof X509) {
            $this->{$type . 'Key'} = new Key(
                $this->certificate->{$type . 'Key'},
                $this->keyAlgorithm,
                [
                    'type' => $type
                ]
            );
        }
    }
}
