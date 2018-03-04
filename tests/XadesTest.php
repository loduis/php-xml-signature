<?php

namespace XML\Tests;

use XML\Signature;
use XML\Signature\X509;

class XadesTest extends TestCase
{
    public function testShouldCreateXml()
    {
        $certificate = X509::fromFile(__DIR__ . '/utils/cert.pem');
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
                        'serial_number' => '9128602840918470673'
                    ],
                    [
                        'raw' => 'prueba2',
                        'issuer_name' => 'C=CO,L=Bogota D.C.,O=Andes SCD,OU=Division de certificacion,CN=ROOT CA ANDES SCD S.A.,1.2.840.113549.1.9.1=#1614696e666f40616e6465737363642e636f6d2e636f',
                        'serial_number' => '7958418607150926283'
                    ],
                    [
                        'raw' => 'prueba3',
                        'issuer_name' => 'C=CO,L=Bogota D.C.,O=Andes SCD,OU=Division de certificacion,CN=ROOT CA ANDES SCD S.A.,1.2.840.113549.1.9.1=#1614696e666f40616e6465737363642e636f6d2e636f',
                        'serial_number' => '3248112716520923666'
                    ]
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
