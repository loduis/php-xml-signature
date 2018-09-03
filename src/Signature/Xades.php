<?php

namespace XML\Signature;

use XML\Element;
use XML\Signature;
use function XML\str_camel;

class Xades implements \ArrayAccess
{
    public $id;

    public $time;

    public $role;

    public $algorithm;

    public $identifier;

    public $policyHash;

    public $certs = [];

    public $target;

    public $referenceId;

    public function __construct(array $options = [])
    {
        if (!($options['time'] ?? false)) {
            $options['time'] = gmdate('Y-m-d\TH:i:s\Z');
        }
        foreach ($options as $key => $value) {
            $key = str_camel($key);
            $this->$key = $value;
        }
    }

    public function appendInto($object)
    {
        $qualifyingProperties = $object->add('xades:QualifyingProperties', [
            'xmlns:xades' => 'http://uri.etsi.org/01903/v1.3.2#',
            // 'xmlns:ds' => Signature::NS,
            'xmlns:xades141' => 'http://uri.etsi.org/01903/v1.4.1#',
            'Target' => '#' . $this->target
        ]);

        $signedProperties = $qualifyingProperties->SignedProperties([
            'Id' => $this->id
        ]);

        $signedProperties->SignedSignatureProperties(function ($signedSignatureProperties) {
            $signedSignatureProperties->SigningTime($this->time);
            $this->createCertificate($signedSignatureProperties);
            $this->createIdentifier($signedSignatureProperties);
            $this->createRole($signedSignatureProperties);
        });

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
                                    Digest::importInto(
                                        $certDigest,
                                        $this->algorithm,
                                        $value['raw']
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

    protected function createRole($signedSignatureProperties)
    {
        if ($this->role) {
            $signedSignatureProperties->SignerRole()
                ->ClaimedRoles()
                ->ClaimedRole($this->role);
        }
    }

    private function getPolicyHash()
    {
        return $this->policyHash;
    }

    public function offsetSet($offset, $value)
    {
        $offset = str_camel($offset);
        $this->$offset = $value;
    }

    public function offsetExists($offset)
    {
        $offset = str_camel($offset);

        return isset($this->$offset);
    }

    public function offsetUnset($offset)
    {
        $offset = str_camel($offset);
        unset($this->$offset);
    }

    public function offsetGet($offset)
    {
        $offset = str_camel($offset);

        return $this->$offset ?? null;
    }
}
