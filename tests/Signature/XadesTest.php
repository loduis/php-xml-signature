<?php

namespace XML\Tests\Signature;

use XML\Tests\TestCase;
use XML\Signature\Xades;
use XML\Signature\Digest;

class XadesTest extends TestCase
{
    public function testShouldCreateXml()
    {
        $xades = new Xades([
            'id' => 'xmldsig-88fbfc45-3be2-4c4a-83ac-0796e1bad4c5-signedprops',
            'target' => 'xmldsig-88fbfc45-3be2-4c4a-83ac-0796e1bad4c5',
            'algorithm' => Digest::SHA1,
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
        ]);
        $element = $xades->create();
        $this->assertMatchesXmlSnapshot($element->pretty());
    }
}
