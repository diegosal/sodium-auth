<?php

namespace Ns147\SodiumAuth\Console;

use ParagonIE\Halite\ {
    HiddenString,
    Symmetric\AuthenticationKey,
    Symmetric\EncryptionKey,
    Asymmetric\EncryptionSecretKey,
    Asymmetric\EncryptionPublicKey
};
use Illuminate\Support\Str;
use Illuminate\Console\Command;

class SodiumSecretCommand extends Command
{
    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = 'sodium:secret
        {--s|show : Display the key instead of modifying files.}
        {--f|force : Skip confirmation when overwriting an existing key.}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Set the SodiumAuth secret key used to sign the tokens';

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        $enc_key = Str::random(32);
        $auth_key = Str::random(32);

        $enc_private_key = Str::random(32);
        $enc_public_key = Str::random(32);

        $enc_secret = new EncryptionKey(
            new HiddenString($enc_key)
        );
        $auth_secret = new AuthenticationKey(
            new HiddenString($auth_key)
        );

        $enc_private_secret = new EncryptionSecretKey(
            new HiddenString($enc_private_key)
        );

        $enc_public_secret = new EncryptionPublicKey(
            new HiddenString($enc_public_key)
        );

        if ($this->option('show')) {
            $this->comment($enc_secret->getRawKeyMaterial());
            $this->comment($auth_secret->getRawKeyMaterial());
            $this->comment($enc_private_secret->getRawKeyMaterial());
            $this->comment($enc_public_secret->getRawKeyMaterial());
            return;
        }

        if (file_exists($path = $this->envPath()) === false) {
            return $this->displayKey($key);
        }

        if (Str::contains(file_get_contents($path), 'SODIUM_SECRET_KEY') === false &&
            Str::contains(file_get_contents($path), 'SODIUM_AUTH_KEY') === false &&
            Str::contains(file_get_contents($path), 'SODIUM_PRIVATE_KEY') === false &&
            Str::contains(file_get_contents($path), 'SODIUM_PUBLIC_KEY') === false) {
            // update existing entry
            file_put_contents($path, PHP_EOL."SODIUM_SECRET_KEY=$enc_secret->getRawKeyMaterial()", FILE_APPEND);
            file_put_contents($path, PHP_EOL."SODIUM_AUTH_KEY=$auth_secret->getRawKeyMaterial()", FILE_APPEND);
            file_put_contents($path, PHP_EOL."SODIUM_PRIVATE_KEY=$enc_private_secret->getRawKeyMaterial()", FILE_APPEND);
            file_put_contents($path, PHP_EOL."SODIUM_PUBLIC_KEY=$enc_public_secret->getRawKeyMaterial()", FILE_APPEND);
        } else {
            if ($this->isConfirmed() === false) {
                $this->comment('Phew... No changes were made to your secret key.');
                return;
            }

            // create new entry
            file_put_contents($path, str_replace(
                'SODIUM_SECRET_KEY='.$this->laravel['config']['sodium.secret.key'],
                'SODIUM_SECRET_KEY='.$enc_secret->getRawKeyMaterial(), file_get_contents($path),

                'SODIUM_AUTH_KEY='.$this->laravel['config']['sodium.auth.key'],
                'SODIUM_AUTH_KEY='.$auth_secret->getRawKeyMaterial(), file_get_contents($path),

                'SODIUM_PRIVATE_KEY='.$this->laravel['config']['sodium.private.key'],
                'SODIUM_PRIVATE_KEY='.$enc_private_secret->getRawKeyMaterial(), file_get_contents($path),

                'SODIUM_PUBLIC_KEY='.$this->laravel['config']['sodium.public.key'],
                'SODIUM_PUBLIC_KEY='.$enc_public_secret->getRawKeyMaterial(), file_get_contents($path)
            ));
        }

        $this->displayKey(
            $enc_secret->getRawKeyMaterial(),
            $auth_secret->getRawKeyMaterial(),
            $enc_private_secret->getRawKeyMaterial(),
            $enc_public_secret->getRawKeyMaterial()
        );
    }

    /**
     * Display the key.
     *
     * @param  string  $key
     *
     * @return void
     */
    protected function displayKey(
        $enc_secret,
        $auth_secret,
        $enc_private_secret,
        $enc_public_secret
    )
    {
        $this->laravel['config']['sodium.secret.key'] = $enc_secret;
        $this->laravel['config']['sodium.auth.key'] = $auth_secret;
        $this->laravel['config']['sodium.private.key'] = $enc_private_secret;
        $this->laravel['config']['sodium.public.key'] = $enc_public_secret;

        $this->info("sodium-auth secret [$enc_secret] set successfully.");
        $this->info("sodium-auth auth [$auth_secret] set successfully.");
        $this->info("sodium-auth private [$enc_private_secret] set successfully.");
        $this->info("sodium-auth public [$enc_public_secret] set successfully.");
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