<?php

namespace Ns147\SodiumAuth\Console;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Ns147\SodiumAuth\Console\GenerateCommand;
use Throwable;

final class GenerateSharedEncryptionKey extends GenerateCommand
{
    /** @var string */
    protected $signature = 'sodium:generate:shared:encryption
                    {--show : Display the key instead of modifying files}
                    {--force : Force the operation to run when in production}';

    /** @var string */
    protected $description = 'Set Sapient shared encryption key.';

    /**
     * @return void
     */
    public function handle()
    {
        $key = Base64UrlSafe::encode(random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES));

        if ($this->option('show')) {
            $this->comment('<comment>Key: ' . $key . '</comment>');

            return;
        }
        $option = '';
        if ($this->input->hasOption('force') && $this->option('force'))
            $option = 'force';
        else
            $option = '';
        if ($this->confirmOverwrite('shared', 'encryption_key', $option)) {
            $this->writeConfigurationValue('SAPIENT_SHARED_ENCRYPTION_KEY', $key);

            $this->info("Sapient shared encryption key set successfully.");
        } else {
            $this->comment('Phew... No changes were made to the key.');
        }

        try {
            sodium_memzero($key);
        } catch (Throwable $exception) {
            //
        }
    }
}
