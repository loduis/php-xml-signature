<?php

namespace XML\Tests;

use XML\Signature;
use XML\Signature\Digest;
use XML\Signature\Key;
use XML\Signature\X509;
use XML\Signature\Xades;

class XadesTest extends TestCase
{
    public function testShouldCreateXmlWithCustomCerts()
    {
        $certificate = X509::fromFile(Cert::file('pem'));
        $signature = new Signature([
            'id' => 'signature',
            'key_info_id' => 'keyInfo',
            'certificate' => $certificate,
            'xades' => [
                'id' => 'signedprops',
                'time' => '2016-07-12T11:17:38.639-05:00',
                'role' => 'supplier',
                'identifier' => 'https://facturaelectronica.dian.gov.co/politicadefirma/v1/politicadefirmav1.pdf',
                'policy_hash' => '61fInBICBQOCBwuTwlaOZSi9HKc=',
                'certs' => [
                    [
                        'raw' => 'prueba1',
                        'issuer_name' => 'C=CO,L=Bogota D.C.,O=Andes SCD.,OU=Division de certificacion entidad final,CN=CA ANDES SCD S.A. Clase II,1.2.840.113549.1.9.1=#1614696e666f40616e6465737363642e636f6d2e636f',
                        'serial_number' => '9128602840918470673',
                        'digest_value' => 'CWRZ6T8gorOatsXd1JPkT1i8OpE='
                    ],
                    [
                        'raw' => 'prueba2',
                        'issuer_name' => 'C=CO,L=Bogota D.C.,O=Andes SCD,OU=Division de certificacion,CN=ROOT CA ANDES SCD S.A.,1.2.840.113549.1.9.1=#1614696e666f40616e6465737363642e636f6d2e636f',
                        'serial_number' => '7958418607150926283',
                        'digest_value' => '2MdGh3SWIpDtWUwz55wsIZssL0I='
                    ],
                    [
                        'raw' => 'prueba3',
                        'issuer_name' => 'C=CO,L=Bogota D.C.,O=Andes SCD,OU=Division de certificacion,CN=ROOT CA ANDES SCD S.A.,1.2.840.113549.1.9.1=#1614696e666f40616e6465737363642e636f6d2e636f',
                        'serial_number' => '3248112716520923666',
                        'digest_value' => '7l7ZXDfZm3oHmBzjvala0kbXhOU='
                    ]
                ],
                'namespaces' => [
                    'xades141' => 'http://uri.etsi.org/01903/v1.4.1#'
                ]
            ]
        ]);
        $doc = new \DOMDocument();
        $doc->loadXML('<test/>');
        $signature->sign($doc);
        $this->assertTrue($signature->verify());
        $this->assertMatchesXmlSnapshot((string) $signature);
    }

    public function testShouldCreateXmlWithDateFormatAndCustomCerts()
    {
        $certificate = X509::fromFile(Cert::file('pem'));
        $signature = new Signature([
            'key_algorithm' => Key::RSA_SHA1,
            'digest_algorithm' => Digest::SHA1,
            'id' => 'Signature620397',
            'key_info_id' => 'keyInfo',
            'reference_id' => 'Reference-ID-363558',
            'reference_uri' => '#comprobante',
            'key_info_id' => 'Certificate1562780',
            'object_id' => 'Signature620397-Object231987',
            'certificate' => $certificate,
            'namespaces' => [
                'etsi' => Xades::NS,
            ],
            'modulus' => true,
            'xades' => [
                'id' => 'Signature620397-SignedProperties24123',
                'time' => '2012-03-05T16:57:32-05:00',
                'certs' => [
                    [
                        'raw' => 'prueba1',
                        'issuer_name' => 'CN=AC BANCO CENTRAL DEL ECUADOR,L=QUITO,OU=ENTIDAD DE CERTIFICACION DE INFORMACION-ECIBCE,O=BANCO CENTRAL DEL ECUADOR,C=EC',
                        'serial_number' => '1312833444',
                        'digest_value' => 'xUQewsj7MrjSfyMnhWz5DhQnWJM='
                    ],
                ],
                'format' => [
                    'description' => 'contenido comprobante',
                    'type' => 'text/xml'
                ]
            ]
        ]);
        $doc = new \DOMDocument();
        $doc->loadXML('<test/>');
        $signature->sign($doc);
        $this->assertTrue($signature->verify());
        $this->assertMatchesXmlSnapshot((string) $signature);
    }

    public function testShouldCreateXml()
    {
        $certificate = X509::fromFile(Cert::file('pem'));
        $signature = new Signature([
            'certificate' => $certificate,
            'id' => 'signature',
            'key_info_id' => 'keyInfo',
            'xades' => [
                'id' => 'signedprops',
                'time' => '2016-07-12T11:17:38.639-05:00',
                'role' => 'supplier',
                'identifier' => 'https://facturaelectronica.dian.gov.co/politicadefirma/v1/politicadefirmav1.pdf',
                'policy_hash' => '61fInBICBQOCBwuTwlaOZSi9HKc=',
                'namespaces' => [
                    'xades141' => 'http://uri.etsi.org/01903/v1.4.1#'
                ]
            ]
        ]);
        $doc = new \DOMDocument();
        $doc->loadXML('<test/>');
        $signature->sign($doc);
        $this->assertTrue($signature->verify());
        $this->assertMatchesXmlSnapshot((string) $signature);
    }
}
