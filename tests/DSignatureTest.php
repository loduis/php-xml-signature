<?php

namespace XML\Tests;

use DOMDocument;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class DSignatureTest extends TestCase
{
    public function testShouldCreateXml()
    {
        $doc = new DOMDocument('1.0');
        $doc->preserveWhiteSpace = false;
        $doc->loadXML('<test/>');

        // Create a new Security object
        $objDSig = new XMLSecurityDSig();
        // Use the c14n exclusive canonicalization
        $objDSig->setCanonicalMethod(XMLSecurityDSig::C14N);
        // Sign using SHA-256
        $objDSig->addReference(
            $doc,
            XMLSecurityDSig::SHA1,
            array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'),
            ['force_uri' => true]
        );

        // Create a new (private) Security key
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'private'));

        // Add the associated public key to the signature
        $objDSig->add509Cert(file_get_contents(__DIR__ . '/utils/cert.pem'));

        /*
        If key has a passphrase, set it using
        $objKey->passphrase = '<passphrase>';
        */
        // Load the private key
        $objKey->loadKey(__DIR__ . '/utils/cert.pem', TRUE);

        // Sign the XML file
        $objDSig->sign($objKey);

        // Append the signature to the XML
        $objDSig->appendSignature($doc->documentElement);

        $doc->formatOutput = true;
        $doc->loadXML($doc->saveXML());
        // $doc->formatOutput = true;
        // $doc->preserveWhiteSpace = false;

        echo $doc->saveXML();
    }
}
