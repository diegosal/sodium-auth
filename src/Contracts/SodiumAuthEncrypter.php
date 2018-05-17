<?php

namespace Ns147\SodiumAuth\Contracts;

use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Encryption\BaseEncrypter;
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\Crypto as Symmetric;

class SodiumAuthEncrypter implements EncrypterContract
{
    /**
     * Create a new encrypter instance.
     *
     * @param string $key
     */
    public function __construct($key)
    {
        $this->key = $key;
    }

    /**
     * Encrypt the given value.
     *
     * @param string $value
     *
     * @return string
     */
    public function encrypt($value, $serialize = true)
    {
        $encryptionKey = KeyFactory::loadEncryptionKey($this->key);
        $value = new HiddenString($value);
        return Symmetric::encrypt($value, $encryptionKey);
    }

    /**
     * Decrypt the given value.
     *
     * @param string $payload
     *
     * @return string
     */
    public function decrypt($payload, $unserialize = true)
    {
        $encryptionKey = KeyFactory::loadEncryptionKey($this->key);
        $decrypted = Symmetric::decrypt($payload, $encryptionKey);
        return $unserialize ? $decrypted->getString() : $decrypted;
    }
}
