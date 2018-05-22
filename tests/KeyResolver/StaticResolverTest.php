<?php

namespace Ns147\SodiumAuth\Test\KeyResolver;

use Tests\TestCase;
use Ns147\SodiumAuth\KeyResolver\StaticResolver;

class StaticResolverTest extends TestCase
{
    public function testResolveKey()
    {
        $key = 'foo';
        $resolver = new StaticResolver($key);
        static::assertEquals($key, $resolver->resolveKey());
    }
}
