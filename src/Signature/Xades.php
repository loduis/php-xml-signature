<?php

namespace XML\Signature;

use XML\Signature;
use function XML\str_camel;

class Xades implements \ArrayAccess
{
    public const NS = 'http://uri.etsi.org/01903/v1.3.2#';

    public const NS_PROPS = 'http://uri.etsi.org/01903#SignedProperties';

    public $id;

    public $time;

    public $role;

    public $algorithm;

    public $identifier;

    public $policyHash;

    public $certs = [];

    public array $namespaces = [];

    public array $format = [];

    public $target;

    public $prefix = 'xades';

    public $referenceId;

    public function __construct(array $options = [])
    {
        foreach ($options as $key => $value) {
            $key = str_camel($key);
            $this->$key = $value;
        }
    }

    public function appendInto($object)
    {
        $qualifyingProperties = $object->add($this->prefix . ':QualifyingProperties', [
            'Target' => '#' . $this->target,
        ] + [
            'xmlns:' . $this->prefix => static::NS,
            'xmlns:ds' => Signature::NS,

        ] + ensure_xmlns($this->namespaces));

        $signedProperties = $qualifyingProperties->SignedProperties([
            'Id' => $this->id
        ]);

        $signedProperties->SignedSignatureProperties(function ($signedSignatureProperties) {
            $signedSignatureProperties->SigningTime($this->getTime());
            $this->createCertificate($signedSignatureProperties);
            $this->createIdentifier($signedSignatureProperties);
            $this->createRole($signedSignatureProperties);
        });

        if ($this->format) {
            $signedProperties->SignedDataObjectProperties(function ($signedDataObjectProperties) {
                $this->createFormat($signedDataObjectProperties);
            });
        }

        return $signedProperties;
    }

    protected function createCertificate($signedSignatureProperties)
    {
        $signedSignatureProperties->SigningCertificate(
            function ($signingCertificate) {
                foreach ($this->certs as $value) {
                    $signingCertificate->Cert(
                        function ($cert) use ($value) {
                            $cert->CertDigest(
                                function ($certDigest) use ($value) {
                                    $certDigest->DigestMethod([
                                        'Algorithm' => $this->algorithm
                                    ], Signature::NS);

                                    $certDigest->DigestValue(
                                        $value['digest_value'],
                                        Signature::NS
                                    );
                                }
                            );
                            $cert->IssuerSerial(
                                function ($issuerSerial) use ($value) {
                                    $issuerSerial->X509IssuerName(
                                        $value['issuer_name'],
                                        Signature::NS
                                    );
                                    $issuerSerial->X509SerialNumber(
                                        $value['serial_number'],
                                        Signature::NS
                                    );
                                }
                            );
                        }
                    );
                }
            }
        );
    }

    protected function createIdentifier($signedSignatureProperties)
    {
        if ($this->identifier) {
            $signedSignatureProperties->SignaturePolicyIdentifier(
                function ($signaturePolicyIdentifier) {
                    $signaturePolicyIdentifier->SignaturePolicyId(
                        function ($signaturePolicyId) {
                            $signaturePolicyId->SigPolicyId()
                                ->Identifier($this->identifier);
                            $signaturePolicyId->SigPolicyHash(
                                function ($sigPolicyHash) {
                                    $sigPolicyHash->DigestMethod([
                                        'Algorithm' => $this->algorithm
                                    ], Signature::NS);
                                    $sigPolicyHash->DigestValue(
                                        $this->getPolicyHash(),
                                        Signature::NS
                                    );
                                }
                            );
                        }
                    );
                }
            );
        }
    }

    protected function createRole($signedSignatureProperties)
    {
        if ($this->role) {
            $signedSignatureProperties->SignerRole()
                ->ClaimedRoles()
                ->ClaimedRole($this->role);
        }
    }

    protected function createFormat($signedDataObjectProperties)
    {
        if ($this->format) {
            $dataObjectFormat = $signedDataObjectProperties->DataObjectFormat([
                'ObjectReference' => '#' . $this->format['reference']
            ]);
            $dataObjectFormat->Description($this->format['description']);
            $dataObjectFormat->MimeType($this->format['type']);
        }
    }

    private function getPolicyHash()
    {
        return $this->policyHash;
    }

    public function offsetSet($offset, $value): void
    {
        $offset = str_camel($offset);
        $this->$offset = $value;
    }

    public function offsetExists($offset): bool
    {
        $offset = str_camel($offset);

        return isset($this->$offset);
    }

    public function offsetUnset($offset): void
    {
        $offset = str_camel($offset);
        unset($this->$offset);
    }

    public function offsetGet($offset)
    {
        $offset = str_camel($offset);

        return $this->$offset ?? null;
    }

    protected function getTime()
    {
        return $this->time ?? gmdate('Y-m-d\TH:i:s\Z');
    }
}
