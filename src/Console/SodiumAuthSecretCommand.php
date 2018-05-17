<?php

namespace Ns147\SodiumAuth\Console;

use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\KeyFactory;
use Illuminate\Support\Str;
use Illuminate\Console\Command;

class SodiumAuthSecretCommand extends Command
{
    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = 'sodium:make
        {--path= : The path to save key outside webroot.}
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

            if (file_exists($path = $this->envPath()) === false) {
                return $this->displayKey(
                    $pPath,
                    $ePath
                );
            }

            if (Str::contains(file_get_contents($pPath), 'SODIUM_AUTH_P_PATH') === false &&
                Str::contains(file_get_contents($ePath), 'SODIUM_AUTH_E_PATH') === false) {
                file_put_contents(
                    $path,
                    PHP_EOL."SODIUM_AUTH_P_PATH=$pPath",
                    FILE_APPEND
                );
                file_put_contents(
                    $path,
                    PHP_EOL."SODIUM_AUTH_E_PATH=$ePath",
                    FILE_APPEND
                );
            } else {
                if ($this->isConfirmed() === false) {
                    $this->comment('Phew... No changes were made to your secret key.');
                    return;
                }

                // create new entry
                file_put_contents(
                    $path,
                    str_replace(
                        'SODIUM_AUTH_P_PATH='.$this->laravel['config']['sodium.p_path'],
                        'SODIUM_AUTH_P_PATH='.$pPath,
                        file_get_contents($pPath)
                    )
                );
                file_put_contents(
                    $path,
                    str_replace(
                        'SODIUM_AUTH_E_PATH='.$this->laravel['config']['sodium.p_path'],
                        'SODIUM_AUTH_E_PATH='.$ePath,
                        file_get_contents($ePath)
                    )
                );
            }

            $this->displayKey(
                $pPath,
                $ePath
            );
        }
    }

    /**
     * Display the key.
     *
     * @param  string  $key
     *
     * @return void
     */
    protected function displayKey(
        $pPath,
        $ePath
    )
    {
        $this->laravel['config']['sodium.p_path'] = $pPath;
        $this->laravel['config']['sodium.e_path'] = $ePath;

        $this->info("sodium-auth secret [$pPath] set successfully.");
        $this->info("sodium-auth auth [$ePath] set successfully.");
    }

    /**
     * Check if the modification is confirmed.
     *
     * @return bool
     */
    protected function isConfirmed()
    {
        return $this->option('force') ? true : $this->confirm(
            'This will invalidate all existing tokens. Are you sure you want to override the secret key?'
        );
    }

    /**
     * Get the .env file path.
     *
     * @return string
     */
    protected function envPath()
    {
        if (method_exists($this->laravel, 'environmentFilePath')) {
            return $this->laravel->environmentFilePath();
        }

        return $this->laravel->basePath('.env');
    }
}
