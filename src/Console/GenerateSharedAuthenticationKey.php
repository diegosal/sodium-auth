<?php

namespace Ns147\SodiumAuth\Console;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Ns147\SodiumAuth\Console\GenerateCommand;
use Throwable;

final class GenerateSharedAuthenticationKey extends GenerateCommand
{
    /** @var string */
    protected $signature = 'sodium:generate:shared:authentication
                    {--show : Display the key instead of modifying files}
                    {--force : Force the operation to run when in production}';

    /** @var string */
    protected $description = 'Set Sapient shared authentication key.';

    /**
     * @return void
     */
    public function handle()
    {
        $key = Base64UrlSafe::encode(random_bytes(SODIUM_CRYPTO_AUTH_KEYBYTES));

        if ($this->option('show')) {
            $this->comment('<comment>Key: ' . $key . '</comment>');
            return;
        }
        $option = '';
        if ($this->input->hasOption('force') && $this->option('force'))
            $option = 'force';
        else
            $option = '';
        if ($this->confirmOverwrite('shared', 'authentication_key', $option)) {
            $this->writeConfigurationValue('SAPIENT_SHARED_AUTHENTICATION_KEY', $key);

            $this->info("Sapient shared authentication key set successfully.");
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
