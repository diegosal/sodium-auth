<?php

namespace Ns147\SodiumAuth\Providers;

use Ns147\SodiumAuth\SodiumAuth;
use Ns147\SodiumAuth\Factory;
use Ns147\SodiumAuth\SAuth;
use Ns147\SodiumAuth\Manager;
use Ns147\SodiumAuth\Guards\SodiumAuthGuard;
use Ns147\SodiumAuth\Blacklist;
use Ns147\SodiumAuth\Http\Parser\Parser;
use Ns147\SodiumAuth\Http\Parser\Cookies;
use Illuminate\Support\ServiceProvider;
use Ns147\SodiumAuth\Http\Middleware\Check;
use Ns147\SodiumAuth\Providers\Token\ApiTokenFactory;
use Ns147\SodiumAuth\Http\Parser\AuthHeaders;
use Ns147\SodiumAuth\Http\Parser\InputSource;
use Ns147\SodiumAuth\Http\Parser\QueryString;
use Ns147\SodiumAuth\Http\Parser\RouteParams;
use Ns147\SodiumAuth\Contracts\Providers\Auth;
use Ns147\SodiumAuth\Contracts\Providers\Storage;
use Ns147\SodiumAuth\Validators\PayloadValidator;
use Ns147\SodiumAuth\Http\Middleware\Authenticate;
use Ns147\SodiumAuth\Http\Middleware\RefreshToken;
use Ns147\SodiumAuth\Claims\Factory as ClaimFactory;
use Ns147\SodiumAuth\Http\Middleware\AuthenticateAndRenew;
use Ns147\SodiumAuth\Contracts\Providers\Token as TokenContract;
use Ns147\SodiumAuth\Console\InstallCommand;
use Ns147\SodiumAuth\Console\EncryptionKeyCommand;
use Ns147\SodiumAuth\Console\GenerateSealingKeyPair;
use Ns147\SodiumAuth\Console\GenerateSharedAuthenticationKey;
use Ns147\SodiumAuth\Console\GenerateSharedEncryptionKey;
use Ns147\SodiumAuth\Console\GenerateSigningKeyPair;
use Ns147\SodiumAuth\Console\GenerateTokenKey;
use Ns147\SodiumAuth\Controller\SodiumAuthController;

abstract class AbstractServiceProvider extends ServiceProvider
{
    /**
     * The middleware aliases.
     *
     * @var array
     */
    protected $middlewareAliases = [
        'sodium.auth' => Authenticate::class,
        'sodium.check' => Check::class,
        'sodium.refresh' => RefreshToken::class,
        'sodium.renew' => AuthenticateAndRenew::class,
    ];

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
        $this->registerAliases();

        $this->registerTokenProvider();
        $this->registerAuthProvider();
        $this->registerStorageProvider();
        $this->registerTokenBlacklist();

        $this->registerManager();
        $this->registerTokenParser();

        $this->registerSodiumAuth();
        $this->registerSAuth();
        $this->registerPayloadValidator();
        $this->registerClaimFactory();
        $this->registerPayloadFactory();

        $this->registerSodiumCommand();
        $this->commands(
            'ns147.sodium.install',
            'ns147.sodium.encryption.key',
            'ns147.sodium.seal.pair.key',
            'ns147.sodium.shared.authentication.key',
            'ns147.sodium.shared.encryption.key',
            'ns147.sodium.signing.key.pair',
            'ns147.sodium.token.key'
        );

    }

    /**
     * Extend Laravel's Auth.
     *
     * @return void
     */
    protected function extendAuthGuard()
    {
        $this->app['auth']->extend('sodium', function ($app, $name, array $config) {
            $guard = new JwtGuard(
                $app['ns147.sodium'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    /**
     * Bind some aliases.
     *
     * @return void
     */
    protected function registerAliases()
    {
        $this->app->alias('ns147.sodium', SodiumAuth::class);
        $this->app->alias('ns147.sodium.auth', SAuth::class);
        $this->app->alias('ns147.sodium.provider.sodium', TokenContract::class);
        $this->app->alias('ns147.sodium.provider.sodium.apitokenfactory', ApiTokenFactory::class);
        $this->app->alias('ns147.sodium.provider.auth', Auth::class);
        $this->app->alias('ns147.sodium.provider.storage', Storage::class);
        $this->app->alias('ns147.sodium.manager', Manager::class);
        $this->app->alias('ns147.sodium.blacklist', Blacklist::class);
        $this->app->alias('ns147.sodium.payload.factory', Factory::class);
        $this->app->alias('ns147.sodium.validators.payload', PayloadValidator::class);
    }

    /**
     * Register the bindings for the Web Token provider.
     *
     * @return void
     */
    protected function registerTokenProvider()
    {
        $this->registerTokenFactoryProvider();

        $this->app->singleton('ns147.sodium.provider.sodium', function ($app) {
            return $this->getConfigInstance('providers.sodium');
        });
    }


    /**
     * Register the bindings for the Token provider.
     *
     * @return void
     */
    protected function registerTokenFactoryProvider()
    {
        $this->app->singleton('ns147.sodium.provider.sodium.apitokenfactory', function ($app) {
            return new ApiTokenFactory(
                $this->config('paseto.private_key'),
                $this->config('paseto.public_key'),
                $this->config('paseto.shared_key'),
                $this->config('ttl')
            );
        });
    }

    /**
     * Register the bindings for the Auth provider.
     *
     * @return void
     */
    protected function registerAuthProvider()
    {
        $this->app->singleton('ns147.sodium.provider.auth', function () {
            return $this->getConfigInstance('providers.auth');
        });
    }

    /**
     * Register the bindings for the Storage provider.
     *
     * @return void
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('ns147.sodium.provider.storage', function () {
            return $this->getConfigInstance('providers.storage');
        });
    }

    /**
     * Register the bindings for the JWT Manager.
     *
     * @return void
     */
    protected function registerManager()
    {
        $this->app->singleton('ns147.sodium.manager', function ($app) {
            $instance = new Manager(
                $app['ns147.sodium.provider.sodium'],
                $app['ns147.sodium.blacklist'],
                $app['ns147.sodium.payload.factory']
            );

            return $instance->setBlacklistEnabled((bool) $this->config('blacklist_enabled'))
                            ->setPersistentClaims($this->config('persistent_claims'));
        });
    }

    /**
     * Register the bindings for the Token Parser.
     *
     * @return void
     */
    protected function registerTokenParser()
    {
        $this->app->singleton('ns147.sodium.parser', function ($app) {
            $parser = new Parser(
                $app['request'],
                [
                    new AuthHeaders,
                    new QueryString,
                    new InputSource,
                    new RouteParams,
                    new Cookies($this->config('decrypt_cookies')),
                ]
            );

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });
    }

    /**
     * Register the bindings for the main Auth class.
     *
     * @return void
     */
    protected function registerSodiumAuth()
    {
        $this->app->singleton('ns147.sodium', function ($app) {
            return (new SodiumAuth(
                $app['ns147.sodium.manager'],
                $app['ns147.sodium.parser']
            ))->lockSubject($this->config('lock_subject'));
        });
    }

    /**
     * Register the bindings for the main SAuth class.
     *
     * @return void
     */
    protected function registerSAuth()
    {
        $this->app->singleton('ns147.sodium.auth', function ($app) {
            return new SAuth(
                $app['ns147.sodium.manager'],
                $app['ns147.sodium.provider.auth'],
                $app['ns147.sodium.parser']
            );
        });
    }

    /**
     * Register the bindings for the Blacklist.
     *
     * @return void
     */
    protected function registerTokenBlacklist()
    {
        $this->app->singleton('ns147.sodium.blacklist', function ($app) {
            $instance = new Blacklist($app['ns147.sodium.provider.storage']);

            return $instance->setGracePeriod($this->config('blacklist_grace_period'))
                            ->setRefreshTTL($this->config('refresh_ttl'));
        });
    }

    /**
     * Register the bindings for the payload validator.
     *
     * @return void
     */
    protected function registerPayloadValidator()
    {
        $this->app->singleton('ns147.sodium.validators.payload', function () {
            return (new PayloadValidator)
                ->setRefreshTTL($this->config('refresh_ttl'))
                ->setRequiredClaims($this->config('required_claims'));
        });
    }

    /**
     * Register the bindings for the Claim Factory.
     *
     * @return void
     */
    protected function registerClaimFactory()
    {
        $this->app->singleton('ns147.sodium.claim.factory', function ($app) {
            $factory = new ClaimFactory($app['request']);
            $app->refresh('request', $factory, 'setRequest');

            return $factory->setTTL($this->config('ttl'))
                           ->setLeeway($this->config('leeway'));
        });
    }

    /**
     * Register the bindings for the Payload Factory.
     *
     * @return void
     */
    protected function registerPayloadFactory()
    {
        $this->app->singleton('ns147.sodium.payload.factory', function ($app) {
            return new Factory(
                $app['ns147.sodium.claim.factory'],
                $app['ns147.sodium.validators.payload']
            );
        });
    }

    /**
     * Helper to get the config values.
     *
     * @param  string  $key
     * @param  string  $default
     *
     * @return mixed
     */
    protected function config($key, $default = null)
    {
        return config("sodium.$key", $default);
    }

    /**
     * Get an instantiable configuration instance.
     *
     * @param  string  $key
     *
     * @return mixed
     */
    protected function getConfigInstance($key)
    {
        $instance = $this->config($key);

        if (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }

    protected function registerSodiumCommand()
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
        $this->app->singleton('ns147.sodium.token.key', function () {
            return new GenerateTokenKey;
        });
    }
}
