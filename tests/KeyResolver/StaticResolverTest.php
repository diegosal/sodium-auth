<?php

namespace Ns147\SodiumAuth\Test\KeyResolver;

use Ns147\SodiumAuth\Test\KeyResolver\TestCase;

final class StaticResolverTest extends TestCase
{
    public function testResolveKey()
    {
        $key = 'foo';
        $resolver = new StaticResolver($key);

        static::assertEquals($key, $resolver->resolveKey());
    }
}
