<?php

namespace Ns147\SodiumAuth\Test\Stubs;

use Ns147\SodiumAuth\Providers\Token\TokenProvider;

class TokenProviderStub extends TokenProvider
{
    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric()
    {
        return false;
    }
}
