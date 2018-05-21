<?php

namespace Ns147\SodiumAuth\KeyResolver;

interface Resolver
{
    /**
     * @return string Base64UrlSafe-encoded
     */
    public function resolveKey(): string;
}
