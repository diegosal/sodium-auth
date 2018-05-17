<?php

namespace Ns147\SodiumAuth\Contracts;

use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Password;

class SodiumAuthHasher implements HasherContract
{
    /**
     * The default memory cost factor.
     *
     * @var string
     */
    protected $key;

    /**
     * Create a new hasher instance.
     *
     * @param  string  $key
     * @return void
     */
    public function __construct($key)
    {
        $this->key = $key;
    }

    /**
     * Get information about the given hashed value.
     *
     * @param  string  $unusedHedValue
     * @return array
     */
    public function info($unusedHedValue)
    {
        return;
    }
    /**
     * Check if the given hash has been hashed using the given options.
     *
     * @param string $hashedValue
     * @param array  $unusedOptions
     *
     * @return bool
     */
    public function needsRehash($hashedValue, array $unusedOptions = [])
    {
        $encryptionKey = KeyFactory::loadEncryptionKey($this->key);

        return needsRehash::needsRehash($hashedValue, $encryptionKey);
    }

    /**
     * Hash the given value.
     *
     * @param string $value
     * @param array  $options
     *
     * @throws \RuntimeException
     *
     * @return string
     * @return string
     */
    public function make($value, array $options = [])
    {
        $encryptionKey = KeyFactory::loadEncryptionKey($this->key);
        $value = new HiddenString($value);

        return Password::hash($value, $encryptionKey);
    }

    /**
     * Check the given plain value against a hash.
     *
     * @param string $value
     * @param string $hashedValue
     * @param array  $unusedOptions Options are not used for Sodium password verification
     *
     * @return bool
     */
    public function check($value, $hashedValue, array $unusedOptions = []
    ): bool {
        $encryptionKey = KeyFactory::loadEncryptionKey($this->key);
        $value = new HiddenString($value);

        return Password::verify($value, $hashedValue, $encryptionKey);
    }
}
