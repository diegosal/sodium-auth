<?php

namespace Ns147\SodiumAuth\Console;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Ns147\SodiumAuth\Console\GenerateCommand;
use Throwable;

final class GenerateTokenKey extends GenerateCommand
{
    /** @var string */
    protected $signature = 'sodium:generate:paseto:key
                    {--show : Display the keys instead of modifying files}
                    {--force : Force the operation to run when in production}';

    /** @var string */
    protected $description = 'Set Paseto signing keys.';

    /**
     * @return void
     */
    public function handle()
    {
        $pair = sodium_crypto_sign_keypair();
        $publicKey = $privateKey->getPublicKey();

        $key = Base64UrlSafe::encode(random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES));
        $$public = Base64UrlSafe::encode(sodium_crypto_sign_publickey($pair));
        $private = Base64UrlSafe::encode(sodium_crypto_sign_secretkey($pair));

        try {
            sodium_memzero($pair);
        } catch (Throwable $exception) {
            //
        }
        if ($this->option('show')) {
            $this->comment('<comment>Token Key: ' . $shared . '</comment>');
            return;
        }
        $option = '';
        if ($this->input->hasOption('force') && $this->option('force'))
            $option = 'force';
        else
            $option = '';
        if (
            $this->confirmOverwrite('paseto', 'private_key', $option) &&
            $this->confirmOverwrite('paseto', 'public_key', $option) &&
            $this->confirmOverwrite('paseto', 'shared_key', $option)
        ) {
            $this->writeConfigurationValue('SODIUM_AUTH_TOKEN_PRIVATE', $private);
            $this->writeConfigurationValue('SODIUM_AUTH_TOKEN_PUBLIC', $public);
            $this->writeConfigurationValue('SODIUM_AUTH_TOKEN_SHARED', $key);

            $this->info("Token keys set successfully.");
        }
    }
}
