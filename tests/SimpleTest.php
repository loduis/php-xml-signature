<?php

namespace XML\Tests;

use DOMDocument;
use XML\Signature;
use XML\Signature\X509;

class SimpleTest extends TestCase
{
    public function testShouldCreateXml()
    {
        $certificate = X509::fromFile(Cert::file('pem'));
        $signature = new Signature([
            'certificate' => $certificate,
        ]);
        $doc = new \DOMDocument();
        $doc->loadXML('<test/>');
        $signature->sign($doc);
        $this->assertTrue($signature->verify());
        $this->assertMatchesXmlSnapshot((string) $signature);
    }
}
