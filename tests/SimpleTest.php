<?php

namespace XML\Tests;

use DOMDocument;
use XML\Signature;
use XML\Signature\X509;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class SimpleTest extends TestCase
{
    public function testShouldCreateXml()
    {
        $certificate = X509::fromFile(__DIR__ . '/utils/cert.pem');
        $signature = new Signature([
            'certificate' => $certificate,
        ]);
        $doc = new \DOMDocument();
        $doc->loadXML('<test/>');
        $signature->sign($doc);
        $this->assertTrue($signature->verify());
        $this->assertMatchesXmlSnapshot((string) $signature);
        $doc->formatOutput = true;
        $this->assertEquals($doc->saveXML(), $this->getByRobRichards());
    }

    protected function getByRobRichards()
    {
        $doc = new DOMDocument('1.0');
        $doc->preserveWhiteSpace = false;
        $doc->loadXML('<test/>');

        // Create a new Security object
        $objDSig = new XMLDsig();
        // Use the c14n exclusive canonicalization
        $objDSig->setCanonicalMethod(XMLSecurityDSig::C14N);
        // Sign using SHA-256
        $objDSig->addReference(
            $doc,
            XMLSecurityDSig::SHA1,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'],
            ['force_uri' => true]
        );

        // Create a new (private) Security key
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, ['type'=>'private']);

        // Add the associated public key to the signature
        $objDSig->add509Cert(file_get_contents(__DIR__ . '/utils/cert.pem'));

        /*
        If key has a passphrase, set it using
        $objKey->passphrase = '<passphrase>';
        */
        // Load the private key
        $objKey->loadKey(__DIR__ . '/utils/cert.pem', true);

        // Sign the XML file
        $objDSig->sign($objKey);

        // Append the signature to the XML
        $objDSig->appendSignature($doc->documentElement);

        $doc->formatOutput = true;
        $doc->loadXML($doc->saveXML());
        $doc->formatOutput = true;
        $doc->preserveWhiteSpace = false;

        return $doc->saveXML();
    }
}


class XMLDsig extends XMLSecurityDSig
{
    public function __construct($prefix='ds')
    {
        $template = preg_replace('/\s/', ' ', self::BASE_TEMPLATE);
        if (! empty($prefix)) {
            $this->prefix = $prefix.':';
            $search = array("<S", "</S", "xmlns=");
            $replace = array("<$prefix:S", "</$prefix:S", "xmlns:$prefix=");
            $template = str_replace($search, $replace, $template);
        }
        $sigdoc = new DOMDocument();
        $sigdoc->loadXML($template);
        $this->sigNode = $sigdoc->documentElement;
    }
}
