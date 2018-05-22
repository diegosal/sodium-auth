<?php

namespace Ns147\SodiumAuth\Providers;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Application as LaravelApplication;
use Illuminate\Support\ServiceProvider;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\CryptographyKeys\SealingPublicKey;
use ParagonIE\Sapient\CryptographyKeys\SealingSecretKey;
use ParagonIE\Sapient\CryptographyKeys\SharedAuthenticationKey;
use ParagonIE\Sapient\CryptographyKeys\SharedEncryptionKey;
use ParagonIE\Sapient\CryptographyKeys\SigningPublicKey;
use ParagonIE\Sapient\CryptographyKeys\SigningSecretKey;
use Ns147\SodiumAuth\Console\InstallCommand;
use Ns147\SodiumAuth\Console\EncryptionKeyCommand;
use Ns147\SodiumAuth\Console\GenerateSealingKeyPair;
use Ns147\SodiumAuth\Console\GenerateSharedAuthenticationKey;
use Ns147\SodiumAuth\Console\GenerateSharedEncryptionKey;
use Ns147\SodiumAuth\Console\GenerateSigningKeyPair;
use Ns147\SodiumAuth\Controller\SodiumAuthController;

abstract class AbstractServiceProvider extends ServiceProvider
{
    /**
     * Boot the service provider.
     *
     * @return void
     */
    abstract public function boot();

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerSodiumCommand();
        $this->commands(
            'ns147.sodium.install',
            'ns147.sodium.encryption.key',
            'ns147.sodium.seal.pair.key',
            'ns147.sodium.shared.authentication.key',
            'ns147.sodium.shared.encryption.key',
            'ns147.sodium.signing.key.pair'
        );
        $this->registerController();
        $this-> registerKey();
    }
    private function registerController()
    {
        $this->app->singleton('', function () {
            return new SodiumAuthController;
        });
    }

    private function registerSodiumCommand()
    {
        $this->app->singleton('ns147.sodium.install', function () {
            return new InstallCommand;
        });
        $this->app->singleton('ns147.sodium.encryption.key', function () {
            return new EncryptionKeyCommand;
        });
        $this->app->singleton('ns147.sodium.seal.pair.key', function () {
            return new GenerateSealingKeyPair;
        });
        $this->app->singleton('ns147.sodium.shared.authentication.key', function () {
            return new GenerateSharedAuthenticationKey;
        });
        $this->app->singleton('ns147.sodium.shared.encryption.key', function () {
            return new GenerateSharedEncryptionKey;
        });
        $this->app->singleton('ns147.sodium.signing.key.pair', function () {
            return new GenerateSigningKeyPair;
        });
    }

    private function registerKey()
    {
        $this->bindKey(SealingPublicKey::class, 'sealing', 'public_key')
            ->bindKey(SealingSecretKey::class, 'sealing', 'private_key')
            ->bindKey(SharedAuthenticationKey::class, 'shared', 'authentication_key')
            ->bindKey(SharedEncryptionKey::class, 'shared', 'encryption_key')
            ->bindKey(SigningPublicKey::class, 'signing', 'public_key')
            ->bindKey(SigningSecretKey::class, 'signing', 'private_key');
    }

    /**
     * @param string $concrete
     * @param string $configKey
     * @return SapientServiceProvider
     */
    private function bindKey(string $concrete, string $part, string $key): self
    {
        /** @var Repository $config */
        $config = $this->app->make('config')->get('sodium');
        $this->app->when($concrete)
            ->needs('$key')
            ->give(function () use ($config, $part, $key) {
                return Base64UrlSafe::decode($config[$part][$key]);
            });
        return $this;
    }


}