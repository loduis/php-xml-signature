<?php

namespace XML;

function str_camel($value)
{
    $value = ucwords(str_replace(['-', '_'], ' ', $value));
    $value = str_replace(' ', '', $value);

    return lcfirst($value);
}
