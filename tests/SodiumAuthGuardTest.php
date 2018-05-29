<?php

namespace Ns147\SodiumAuth\Test;

use Mockery;
use Carbon\Carbon;
use Ns147\SodiumAuth\SAuth;
use Ns147\SodiumAuth\Factory;
use Ns147\SodiumAuth\Payload;
use Ns147\SodiumAuth\Guards\SodiumAuthGuard;
use Illuminate\Http\Request;
use Illuminate\Auth\EloquentUserProvider;
use Ns147\SodiumAuth\Contracts\TokenSubject;
use Illuminate\Contracts\Auth\Authenticatable;

use Tests\TestCase;

class SodiumAuthGuardTest extends TestCase
{
    /**
     * @var \Ns147\SodiumAuth\SAuth|\Mockery\MockInterface
     */
    protected $sodiumAuth;

    /**
     * @var \Illuminate\Contracts\Auth\UserProvider|\Mockery\MockInterface
     */
    protected $provider;

    /**
     * @var \Ns147\SodiumAuth\SodiumAuthGuard|\Mockery\MockInterface
     */
    protected $guard;

    protected $testNowTimestamp;

    public function setUp()
    {
        parent::setUp();

        $this->sodiumAuth = Mockery::mock(SAuth::class);
        $this->provider = Mockery::mock(EloquentUserProvider::class);
        $this->guard = new SodiumAuthGuard($this->sodiumAuth, $this->provider, Request::create('/foo', 'GET'));
        Carbon::setTestNow($now = Carbon::now());
        $this->testNowTimestamp = $now->getTimestamp();
    }

    public function tearDown()
    {
        Carbon::setTestNow();
        Mockery::close();

        parent::tearDown();
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_get_the_request()
    {
        $this->assertInstanceOf(Request::class, $this->guard->getRequest());
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_get_the_authenticated_user_if_a_valid_token_is_provided()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('offsetGet')->once()->with('sub')->andReturn(1);

        $this->sodiumAuth->shouldReceive('setRequest')->andReturn($this->sodiumAuth);
        $this->sodiumAuth->shouldReceive('getToken')->once()->andReturn('foo.bar.baz');
        $this->sodiumAuth->shouldReceive('check')->once()->with(true)->andReturn($payload);
        $this->sodiumAuth->shouldReceive('checkSubjectModel')
                  ->once()
                  ->with('LaravelUserStub')
                  ->andReturn(true);

        $this->provider->shouldReceive('getModel')
                       ->once()
                       ->andReturn('LaravelUserStub');
        $this->provider->shouldReceive('retrieveById')
                       ->once()
                       ->with(1)
                       ->andReturn((object) ['id' => 1]);

        $this->assertSame(1, $this->guard->user()->id);

        // check that the user is stored on the object next time round
        $this->assertSame(1, $this->guard->user()->id);
        $this->assertTrue($this->guard->check());

        // also make sure userOrFail does not fail
        $this->assertSame(1, $this->guard->userOrFail()->id);
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_get_the_authenticated_user_if_a_valid_token_is_provided_and_not_throw_an_exception()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('offsetGet')->once()->with('sub')->andReturn(1);

        $this->sodiumAuth->shouldReceive('setRequest')->andReturn($this->sodiumAuth);
        $this->sodiumAuth->shouldReceive('getToken')->once()->andReturn('foo.bar.baz');
        $this->sodiumAuth->shouldReceive('check')->once()->with(true)->andReturn($payload);
        $this->sodiumAuth->shouldReceive('checkSubjectModel')
                  ->once()
                  ->with('LaravelUserStub')
                  ->andReturn(true);

        $this->provider->shouldReceive('getModel')
                       ->once()
                       ->andReturn('LaravelUserStub');
        $this->provider->shouldReceive('retrieveById')
             ->once()
             ->with(1)
             ->andReturn((object) ['id' => 1]);

        $this->assertSame(1, $this->guard->userOrFail()->id);

        // check that the user is stored on the object next time round
        $this->assertSame(1, $this->guard->userOrFail()->id);
        $this->assertTrue($this->guard->check());
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_return_null_if_an_invalid_token_is_provided()
    {
        $this->sodiumAuth->shouldReceive('setRequest')->andReturn($this->sodiumAuth);
        $this->sodiumAuth->shouldReceive('getToken')->twice()->andReturn('invalid.token.here');
        $this->sodiumAuth->shouldReceive('check')->twice()->andReturn(false);
        $this->sodiumAuth->shouldReceive('getPayload->get')->never();
        $this->provider->shouldReceive('retrieveById')->never();

        $this->assertNull($this->guard->user()); // once
        $this->assertFalse($this->guard->check()); // twice
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_return_null_if_no_token_is_provided()
    {
        $this->sodiumAuth->shouldReceive('setRequest')->andReturn($this->sodiumAuth);
        $this->sodiumAuth->shouldReceive('getToken')->andReturn(false);
        $this->sodiumAuth->shouldReceive('check')->never();
        $this->sodiumAuth->shouldReceive('getPayload->get')->never();
        $this->provider->shouldReceive('retrieveById')->never();

        $this->assertNull($this->guard->user());
        $this->assertFalse($this->guard->check());
    }

    /**
     * @test
     * @group laravel-5.2
     * @expectedException \Ns147\SodiumAuth\Exceptions\UserNotDefinedException
     * @expectedExceptionMessage An error occurred
     */
    public function it_should_throw_an_exception_if_an_invalid_token_is_provided()
    {
        $this->sodiumAuth->shouldReceive('setRequest')->andReturn($this->sodiumAuth);
        $this->sodiumAuth->shouldReceive('getToken')->twice()->andReturn('invalid.token.here');
        $this->sodiumAuth->shouldReceive('check')->twice()->andReturn(false);
        $this->sodiumAuth->shouldReceive('getPayload->get')->never();
        $this->provider->shouldReceive('retrieveById')->never();

        $this->assertFalse($this->guard->check()); // once
        $this->guard->userOrFail(); // twice, throws the exception
    }

    /**
     * @test
     * @group laravel-5.2
     * @expectedException \Ns147\SodiumAuth\Exceptions\UserNotDefinedException
     * @expectedExceptionMessage An error occurred
     */
    public function it_should_throw_an_exception_if_no_token_is_provided()
    {
        $this->sodiumAuth->shouldReceive('setRequest')->andReturn($this->sodiumAuth);
        $this->sodiumAuth->shouldReceive('getToken')->andReturn(false);
        $this->sodiumAuth->shouldReceive('check')->never();
        $this->sodiumAuth->shouldReceive('getPayload->get')->never();
        $this->provider->shouldReceive('retrieveById')->never();

        $this->assertFalse($this->guard->check());
        $this->guard->userOrFail(); // throws the exception
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_return_a_token_if_credentials_are_ok_and_user_is_found()
    {
        $credentials = ['foo' => 'bar', 'baz' => 'bob'];
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveByCredentials')
                       ->once()
                       ->with($credentials)
                       ->andReturn($user);

        $this->provider->shouldReceive('validateCredentials')
                       ->once()
                       ->with($user, $credentials)
                       ->andReturn(true);

        $this->sodiumAuth->shouldReceive('fromUser')
                  ->once()
                  ->with($user)
                  ->andReturn('foo.bar.baz');

        $this->sodiumAuth->shouldReceive('setToken')
                  ->once()
                  ->with('foo.bar.baz')
                  ->andReturnSelf();

        $this->sodiumAuth->shouldReceive('claims')
                  ->once()
                  ->with(['foo' => 'bar'])
                  ->andReturnSelf();

        $token = $this->guard->claims(['foo' => 'bar'])->attempt($credentials);

        $this->assertSame($this->guard->getLastAttempted(), $user);
        $this->assertSame($token, 'foo.bar.baz');
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_return_true_if_credentials_are_ok_and_user_is_found_when_choosing_not_to_login()
    {
        $credentials = ['foo' => 'bar', 'baz' => 'bob'];
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveByCredentials')
                       ->twice()
                       ->with($credentials)
                       ->andReturn($user);

        $this->provider->shouldReceive('validateCredentials')
                       ->twice()
                       ->with($user, $credentials)
                       ->andReturn(true);

        $this->assertTrue($this->guard->attempt($credentials, false)); // once
        $this->assertTrue($this->guard->validate($credentials)); // twice
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_return_false_if_credentials_are_invalid()
    {
        $credentials = ['foo' => 'bar', 'baz' => 'bob'];
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveByCredentials')
                       ->once()
                       ->with($credentials)
                       ->andReturn($user);

        $this->provider->shouldReceive('validateCredentials')
                       ->once()
                       ->with($user, $credentials)
                       ->andReturn(false);

        $this->assertFalse($this->guard->attempt($credentials));
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_magically_call_the_token_instance()
    {
        $this->sodiumAuth->shouldReceive('factory')->andReturn(Mockery::mock(Factory::class));
        $this->assertInstanceOf(Factory::class, $this->guard->factory());
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_logout_the_user_by_invalidating_the_token()
    {
        $this->sodiumAuth->shouldReceive('setRequest')->andReturn($this->sodiumAuth);
        $this->sodiumAuth->shouldReceive('getToken')->once()->andReturn(true);
        $this->sodiumAuth->shouldReceive('invalidate')->once()->andReturn(true);
        $this->sodiumAuth->shouldReceive('unsetToken')->once();

        $this->guard->logout();
        $this->assertNull($this->guard->getUser());
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_refresh_the_token()
    {
        $this->sodiumAuth->shouldReceive('setRequest')->andReturn($this->sodiumAuth);
        $this->sodiumAuth->shouldReceive('getToken')->once()->andReturn(true);
        $this->sodiumAuth->shouldReceive('refresh')->once()->andReturn('foo.bar.baz');

        $this->assertSame($this->guard->refresh(), 'foo.bar.baz');
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_invalidate_the_token()
    {
        $this->sodiumAuth->shouldReceive('setRequest')->andReturn($this->sodiumAuth);
        $this->sodiumAuth->shouldReceive('getToken')->once()->andReturn(true);
        $this->sodiumAuth->shouldReceive('invalidate')->once()->andReturn(true);

        $this->assertTrue($this->guard->invalidate());
    }

    /**
     * @test
     * @group laravel-5.2
     * @expectedException \Ns147\SodiumAuth\Exceptions\TokenException
     * @expectedExceptionMessage Token could not be parsed from the request.
     */
    public function it_should_throw_an_exception_if_there_is_no_token_present_when_required()
    {
        $this->sodiumAuth->shouldReceive('setRequest')->andReturn($this->sodiumAuth);
        $this->sodiumAuth->shouldReceive('getToken')->once()->andReturn(false);
        $this->sodiumAuth->shouldReceive('refresh')->never();

        $this->guard->refresh();
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_generate_a_token_by_id()
    {
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveById')
                       ->once()
                       ->with(1)
                       ->andReturn($user);

        $this->sodiumAuth->shouldReceive('fromUser')
                  ->once()
                  ->with($user)
                  ->andReturn('foo.bar.baz');

        $this->assertSame('foo.bar.baz', $this->guard->tokenById(1));
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_not_generate_a_token_by_id()
    {
        $this->provider->shouldReceive('retrieveById')
                       ->once()
                       ->with(1)
                       ->andReturn(null);

        $this->assertNull($this->guard->tokenById(1));
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_authenticate_the_user_by_credentials_and_return_true_if_valid()
    {
        $credentials = ['foo' => 'bar', 'baz' => 'bob'];
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveByCredentials')
                       ->once()
                       ->with($credentials)
                       ->andReturn($user);

        $this->provider->shouldReceive('validateCredentials')
                       ->once()
                       ->with($user, $credentials)
                       ->andReturn(true);

        $this->assertTrue($this->guard->once($credentials));
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_attempt_to_authenticate_the_user_by_credentials_and_return_false_if_invalid()
    {
        $credentials = ['foo' => 'bar', 'baz' => 'bob'];
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveByCredentials')
                       ->once()
                       ->with($credentials)
                       ->andReturn($user);

        $this->provider->shouldReceive('validateCredentials')
                       ->once()
                       ->with($user, $credentials)
                       ->andReturn(false);

        $this->assertFalse($this->guard->once($credentials));
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_authenticate_the_user_by_id_and_return_boolean()
    {
        $user = new LaravelUserStub;

        $this->provider->shouldReceive('retrieveById')
                       ->twice()
                       ->with(1)
                       ->andReturn($user);

        $this->assertTrue($this->guard->onceUsingId(1)); // once
        $this->assertTrue($this->guard->byId(1)); // twice
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_not_authenticate_the_user_by_id_and_return_false()
    {
        $this->provider->shouldReceive('retrieveById')
                       ->twice()
                       ->with(1)
                       ->andReturn(null);

        $this->assertFalse($this->guard->onceUsingId(1)); // once
        $this->assertFalse($this->guard->byId(1)); // twice
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_create_a_token_from_a_user_object()
    {
        $user = new LaravelUserStub;

        $this->sodiumAuth->shouldReceive('fromUser')
                  ->once()
                  ->with($user)
                  ->andReturn('foo.bar.baz');

        $this->sodiumAuth->shouldReceive('setToken')
                  ->once()
                  ->with('foo.bar.baz')
                  ->andReturnSelf();

        $token = $this->guard->login($user);

        $this->assertSame('foo.bar.baz', $token);
    }

    /**
     * @test
     * @group laravel-5.2
     */
    public function it_should_get_the_payload()
    {
        $this->sodiumAuth->shouldReceive('setRequest')->andReturn($this->sodiumAuth);
        $this->sodiumAuth->shouldReceive('getToken')->once()->andReturn('foo.bar.baz');
        $this->sodiumAuth->shouldReceive('getPayload')->once()->andReturn(Mockery::mock(Payload::class));
        $this->assertInstanceOf(Payload::class, $this->guard->payload());
    }
}

class UserStub implements TokenSubject
{
    public function getTokenIdentifier()
    {
        return 1;
    }

    public function getTokenCustomClaims()
    {
        return [
            'foo' => 'bar',
            'role' => 'admin',
        ];
    }
}

class LaravelUserStub extends UserStub implements Authenticatable, TokenSubject
{
    public function getAuthIdentifierName()
    {
        //
    }

    public function getAuthIdentifier()
    {
        //
    }

    public function getAuthPassword()
    {
        //
    }

    public function getRememberToken()
    {
        //
    }

    public function setRememberToken($value)
    {
        //
    }

    public function getRememberTokenName()
    {
        //
    }
}
