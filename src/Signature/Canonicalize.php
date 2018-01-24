<?php

namespace XML\Signature;

use DOMNode;
use XML\Element;

class Canonicalize
{
    const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';

    const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';

    const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';


    private $options;

    public function __construct($method)
    {
        static $OPTIONS = [
            self::C14N => [
                'exclusive' => false,
                'comments' => false
            ],
            self::C14N_COMMENTS => [
                'exclusive' => false,
                'comments' => true
            ],
            self::EXC_C14N => [
                'exclusive' => true,
                'comments' => false
            ],
            self::EXC_C14N_COMMENTS => [
                'exclusive' => true,
                'comments' => true
            ]
        ];
        $this->options = $OPTIONS[$method];
    }

    public function node($node, $arXPath = null, $prefixList = null)
    {
        if ($node instanceof Element) {
            $node = $node->toElement();
        }
        $withComments = $this->options['comments'];
        if (is_null($arXPath) &&
            ($node instanceof DOMNode) && $node->ownerDocument !== null &&
            $node->isSameNode($node->ownerDocument->documentElement)
        ) {
            $element = $node;
            while ($refnode = $element->previousSibling) {
                if ($refnode->nodeType == XML_PI_NODE ||
                    ($refnode->nodeType == XML_COMMENT_NODE && $withComments)
                ) {
                    break;
                }
                $element = $refnode;
            }
            if ($refnode == null) {
                $node = $node->ownerDocument;
            }
        }

        return $node->C14N(
            $this->options['exclusive'],
            $withComments,
            $arXPath,
            $prefixList
        );
    }
}
