<?php

namespace Ns147\SodiumAuth\Console;

use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\KeyFactory;
use Ns147\SodiumAuth\Console\GenerateCommand;

final class EncryptionKeyCommand extends GenerateCommand
{
    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = 'sodium:encryptionkey
        {--path= : The path to save key outside webroot.}
        {--show : Display the keys instead of modifying files}
        {--f|force : Skip confirmation when overwriting an existing key.}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Set the SodiumAuth secret key files used to make hash';

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        if ($this->input->hasOption('path') && $this->option('path')) {

            $basePath = $this->option('path');

            $secret = new HiddenString(random_bytes(32));
            $salt = random_bytes(16);
            $pKey = KeyFactory::deriveEncryptionKey($secret, $salt);
            $pPath = $basePath.'/sodium-auth-p.key';
            KeyFactory::save($pKey, $pPath);

            $secret = new HiddenString(random_bytes(32));
            $salt = random_bytes(16);
            $eKey = KeyFactory::deriveEncryptionKey($secret, $salt);
            $ePath = $basePath.'/sodium-auth-e.key';
            KeyFactory::save($eKey, $ePath);

            if ($this->option('show')) {
                $this->comment('<comment>Public Key: ' . $pPath . '</comment>');
                $this->comment('<comment>Secret Key: ' . $ePath . '</comment>');
                return;
            }
            $option = '';
            if ($this->input->hasOption('force') && $this->option('force'))
                $option = 'force';
            else
                $option = '';
            if (
                $this->confirmOverwrite('key_path', 'p_path', $option) &&
                $this->confirmOverwrite('key_path', 'e_path', $option)
            ) {
                $this->writeConfigurationValue('SODIUM_AUTH_P_PATH', $pPath);
                $this->writeConfigurationValue('SODIUM_AUTH_E_PATH', $ePath);
                $this->info("keys file create successfully.");
            } else {
                $this->comment('Phew... No changes were made to the key.');
            }
        } else {
            $this->comment('Enter the path for the files.');
        }
    }
}
