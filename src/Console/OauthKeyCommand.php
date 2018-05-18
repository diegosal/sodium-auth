<?php

namespace Ns147\SodiumAuth\Console;

use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\KeyFactory;
use Illuminate\Support\Str;
use Illuminate\Console\Command;

class OauthKeyCommandCommand extends Command
{
    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = 'sodium:oauthkey
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

            if (file_exists($path = $this->envPath()) === false) {
                return $this->displayKey(
                );
            }

            if (Str::contains(file_get_contents($pPath), 'SODIUM_AUTH_P_PATH') === false) {
            } else {
                if ($this->isConfirmed() === false) {
                    $this->comment('Phew... No changes were made to your secret key.');
                    return;
                }
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
    protected function displayKey()
    {
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
