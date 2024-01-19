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

use function XML\Signature\ensure_xmlns;
use function XML\Signature\x509;

class Signature
{
    const NS = 'http://www.w3.org/2000/09/xmldsig#';

    const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    protected $id;

    protected $canonicalMethod = Canonicalize::C14N;

    protected $keyAlgorithm = Key::RSA_SHA256;

    protected $digestAlgorithm = Digest::SHA256;

    protected $xades;

    protected $privateKey;

    protected $publicKey;

    protected $certificate;

    protected $keyInfoId;

    protected $objectId;

    protected $referenceId;

    protected $signatureValueId;

    protected $referenceUri = '';

    private $root;

    private $signedInfo;

    private $value;

    private $data;

    private ?array $modulus = null;

    public function __construct(array $options = [])
    {
        if (($options['certificate'] ?? false)) {
            $options['certificate'] = x509($options['certificate']);
        }
        $modulus = $options['modulus'] ?? false;
        unset($options['modulus']);

        $namespaces = $options['namespaces'] ?? [];
        unset($options['namespaces']);

        foreach ($options as $key => $value) {
            $key = str_camel($key);
            $this->$key = $value;
        }

        foreach (['private', 'public'] as $key) {
            $this->ensureKey($key);
        }

        if ($modulus) {
            $this->modulus = $this->certificate->modulus($this->keyAlgorithm);
        }

        if ($this->xades) {
            $this->xades['target'] = $this->id;
            $this->xades['algorithm'] = $this->digestAlgorithm;
            if (!isset($this->xades['prefix']) && ($prefix = array_search(Xades::NS, $namespaces))) {
                $this->xades['prefix'] = $prefix;
            }
            if (is_array($this->xades)) {
                $this->xades = new Xades($this->xades);
            }
            if ($this->referenceId && !empty($this->xades->format) && !isset($this->xades->format['reference'])) {
                $this->xades->format['reference'] = $this->referenceId;
            }
            if (!($this->xades['certs'] ?? false) && $this->certificate instanceof X509) {
                $this->xades['certs'] = $this->certificate->all(
                    Digest::translateAlgoritm($this->digestAlgorithm)
                );
            }
        }

        $this->root = Element::create('ds:Signature', [
            'Id' => $this->id,
            'xmlns:ds' => static::NS
        ] + ensure_xmlns($namespaces));
    }

    public function time(string $time)
    {
        if ($this->xades) {
            $this->xades->time = $time;
        }
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

    public function isExpired(): bool
    {
        $certs = $this->xades['certs'] ?? $this->certificate->all(
            Digest::translateAlgoritm($this->digestAlgorithm)
        );
        $cert = $certs[0] ?? ['expired_at' => 0];

        return time() > $cert['expired_at'];
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
        $params = [];
        if ($this->signatureValueId) {
            $params['Id'] = $this->signatureValueId;
        }
        $signatureValue = $this->root->SignatureValue($params);
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
                $X509Data->X509Certificate($this->certificate->getValue());
            });
            if ($this->modulus) {
                $keyInfo->KeyValue(function ($keyValue) {
                    foreach ($this->modulus as $key => $value) {
                        $keyValue->{$key . 'KeyValue'}(function ($rSAKeyValue) use ($value) {
                            $rSAKeyValue->Modulus($value['value']);
                            $rSAKeyValue->Modulus($value['exponent']);
                        });

                    }
                });
            }
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
            'URI' => $this->referenceUri
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
