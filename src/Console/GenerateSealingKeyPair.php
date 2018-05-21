<?php

namespace Ns147\SodiumAuth\Console;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Ns147\SodiumAuth\Console\GenerateCommand;
use Throwable;

final class GenerateSealingKeyPair extends GenerateCommand
{
    /** @var string */
    protected $signature = 'sodium:generate:seal:pair
                    {--show : Display the keys instead of modifying files}
                    {--force : Force the operation to run when in production}';

    /** @var string */
    protected $description = 'Set Sapient sealing keys.';

    /**
     * @return void
     */
    public function handle()
    {
        $pair = sodium_crypto_box_keypair();

        $public = Base64UrlSafe::encode(sodium_crypto_box_publickey($pair));
        $private = Base64UrlSafe::encode(sodium_crypto_box_secretkey($pair));

        try {
            sodium_memzero($pair);
        } catch (Throwable $exception) {
            //
        }

        if ($this->option('show')) {
            $this->comment('<comment>Public Key: ' . $public . '</comment>');
            $this->comment('<comment>Secret Key: ' . $private . '</comment>');

            return;
        }
        $option = '';
        if ($this->input->hasOption('force') && $this->option('force'))
            $option = 'force';
        else
            $option = '';
        if (
            $this->confirmOverwrite('sealing', 'public_key',  $option) &&
            $this->confirmOverwrite('sealing', 'private_key',  $option)
        ) {
            $this->writeConfigurationValue('SAPIENT_SEALING_PUBLIC_KEY', $public);
            $this->writeConfigurationValue('SAPIENT_SEALING_PRIVATE_KEY', $private);
            $this->info("Sapient sealing keys set successfully.");
        } else {
            $this->comment('Phew... No changes were made to the key.');
        }
        try {
            sodium_memzero($public);
            sodium_memzero($private);
        } catch (Throwable $exception) {
            //
        }
    }
}
