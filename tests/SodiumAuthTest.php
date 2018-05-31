<?php

namespace Ns147\SodiumAuth\Test;

use Mockery;
use Carbon\Carbon;
use stdClass;
use Ns147\SodiumAuth\Token;
use Ns147\SodiumAuth\Factory;
use Ns147\SodiumAuth\SAuth;
use Ns147\SodiumAuth\Manager;
use Ns147\SodiumAuth\Payload;
use Illuminate\Http\Request;
use Ns147\SodiumAuth\Http\Parser\Parser;
use Ns147\SodiumAuth\Exceptions\TokenException;
use Ns147\SodiumAuth\Contracts\Providers\Auth;
use Ns147\SodiumAuth\Exceptions\TokenInvalidException;
use Ns147\SodiumAuth\Contracts\TokenSubject;
use Tests\TestCase;

class SodiumAuthTest extends TestCase
{
    /**
     * @var \Mockery\MockInterface|\Ns147\SodiumAuth\Manager
     */
    protected $manager;

    /**
     * @var \Mockery\MockInterface|\Ns147\SodiumAuth\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * @var \Mockery\MockInterface|\Ns147\SodiumAuth\Http\Parser\Parser
     */
    protected $parser;

    /**
     * @var \Ns147\SodiumAuth\SAuth
     */
    protected $sodiumAuth;


    protected $testNowTimestamp;

    public function setUp()
    {
        $this->manager = Mockery::mock(Manager::class);
        $this->userStub = UserStub::class;
        $this->auth = Mockery::mock(Auth::class);
        $this->parser = Mockery::mock(Parser::class);
        $this->sodiumAuth = new SAuth($this->manager, $this->auth, $this->parser);
        Carbon::setTestNow($now = Carbon::now());
        $this->testNowTimestamp = $now->getTimestamp();
    }

    public function tearDown()
    {
        Carbon::setTestNow();
        Mockery::close();

        parent::tearDown();
    }

    /** @test */
    public function it_should_return_a_token_when_passing_a_user()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));

        $this->manager
            ->shouldReceive('getPayloadFactory->customClaims')
            ->once()
            ->andReturn($payloadFactory);

        $this->manager->shouldReceive('encode->get')->once()->andReturn('foo.bar.baz');

        $token = $this->sodiumAuth->fromUser(new UserStub);
        $this->assertSame($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_pass_provider_check_if_hash_matches()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));
        $payloadFactory->shouldReceive('get')
                       ->with('prv')
                       ->andReturn(sha1('UserStub'));

        $this->manager->shouldReceive('decode')->once()->andReturn($payloadFactory);

        $this->assertTrue($this->sodiumAuth->setToken('foo.bar.baz')->checkSubjectModel('UserStub'));
    }

    /** @test */
    public function it_should_pass_provider_check_if_hash_matches_when_provider_is_null()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));
        $payloadFactory->shouldReceive('get')
                       ->with('prv')
                       ->andReturnNull();

        $this->manager->shouldReceive('decode')->once()->andReturn($payloadFactory);

        $this->assertTrue($this->sodiumAuth->setToken('foo.bar.baz')->checkSubjectModel('UserStub'));
    }

    /** @test */
    public function it_should_not_pass_provider_check_if_hash_not_match()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));
        $payloadFactory->shouldReceive('get')
                       ->with('prv')
                       ->andReturn(sha1('UserStub1'));

        $this->manager->shouldReceive('decode')->once()->andReturn($payloadFactory);

        $this->assertFalse($this->sodiumAuth->setToken('foo.bar.baz')->checkSubjectModel('UserStub'));
    }

    /** @test */
    public function it_should_return_a_token_when_passing_valid_credentials_to_attempt_method()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));

        $this->manager
             ->shouldReceive('getPayloadFactory->customClaims')
             ->once()
             ->andReturn($payloadFactory);

        $this->manager->shouldReceive('encode->get')->once()->andReturn('foo.bar.baz');

        $this->auth->shouldReceive('byCredentials')->once()->andReturn(true);
        $this->auth->shouldReceive('user')->once()->andReturn(new UserStub);

        $token = $this->sodiumAuth->attempt(['foo' => 'bar']);

        $this->assertSame($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_return_false_when_passing_invalid_credentials_to_attempt_method()
    {
        $this->manager->shouldReceive('encode->get')->never();
        $this->auth->shouldReceive('byCredentials')->once()->andReturn(false);
        $this->auth->shouldReceive('user')->never();

        $token = $this->sodiumAuth->attempt(['foo' => 'bar']);

        $this->assertFalse($token);
    }

    /**
     * @test
     * @expectedException \Ns147\SodiumAuth\Exceptions\TokenException
     * @expectedExceptionMessage A token is required
     */
    public function it_should_throw_an_exception_when_not_providing_a_token()
    {
        $this->sodiumAuth->toUser();
    }

    /** @test */
    public function it_should_return_the_owning_user_from_a_token_containing_an_existing_user()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->once()->with('sub')->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->auth->shouldReceive('byId')->once()->with(1)->andReturn(true);
        $this->auth->shouldReceive('user')->once()->andReturn((object) ['id' => 1]);

        $user = $this->sodiumAuth->setToken('foo.bar.baz')->customClaims(['foo' => 'bar'])->authenticate();

        $this->assertSame($user->id, 1);
    }

    /** @test */
    public function it_should_return_false_when_passing_a_token_not_containing_an_existing_user()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->once()->with('sub')->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->auth->shouldReceive('byId')->once()->with(1)->andReturn(false);
        $this->auth->shouldReceive('user')->never();

        $user = $this->sodiumAuth->setToken('foo.bar.baz')->authenticate();

        $this->assertFalse($user);
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $newToken = Mockery::mock(Token::class);
        $newToken->shouldReceive('get')->once()->andReturn('baz.bar.foo');

        $this->manager->shouldReceive('customClaims->refresh')->once()->andReturn($newToken);

        $result = $this->sodiumAuth->setToken('foo.bar.baz')->refresh();

        $this->assertSame($result, 'baz.bar.foo');
    }

    /** @test */
    public function it_should_invalidate_a_token()
    {
        $token = new Token('foo.bar.baz');

        $this->manager->shouldReceive('invalidate')->once()->with($token, false)->andReturn(true);
        $this->assertInstanceOf(Token::class, $token);
        $this->sodiumAuth->setToken($token)->invalidate();
    }

    /** @test */
    public function it_should_force_invalidate_a_token_forever()
    {
        $token = new Token('foo.bar.baz');

        $this->manager->shouldReceive('invalidate')->once()->with($token, true)->andReturn(true);

        $this->assertInstanceOf(Token::class, $token);
        $this->sodiumAuth->setToken($token)->invalidate(true);
    }

    /** @test */
    public function it_should_retrieve_the_token_from_the_request()
    {
        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');

        $this->assertInstanceOf(Token::class, $this->sodiumAuth->parseToken()->getToken());
        $this->assertEquals($this->sodiumAuth->getToken(), 'foo.bar.baz');
    }

    /** @test */
    public function it_should_get_the_authenticated_user()
    {
        $manager = $this->sodiumAuth->manager();
        $this->assertInstanceOf(Manager::class, $manager);
    }

    /** @test */
    public function it_should_return_false_if_the_token_is_invalid()
    {
        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');
        $this->manager->shouldReceive('decode')->once()->andThrow(new TokenInvalidException);

        $this->assertFalse($this->sodiumAuth->parseToken()->check());
    }

    /** @test */
    public function it_should_return_true_if_the_token_is_valid()
    {
        $payload = Mockery::mock(Payload::class);

        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');
        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->assertTrue($this->sodiumAuth->parseToken()->check());
    }

    /**
     * @test
     * @expectedException \Ns147\SodiumAuth\Exceptions\TokenException
     * @expectedExceptionMessage The token could not be parsed from the request
     */
    public function it_should_throw_an_exception_when_token_not_present_in_request()
    {
        $this->parser->shouldReceive('parseToken')->andReturn(false);

        $this->sodiumAuth->parseToken();
    }

    /** @test */
    public function it_should_return_false_when_no_token_is_set()
    {
        $this->parser->shouldReceive('parseToken')->andReturn(false);

        $this->assertNull($this->sodiumAuth->getToken());
    }

    /** @test */
    public function it_should_magically_call_the_manager()
    {
        $this->manager->shouldReceive('getBlacklist')->andReturn(new stdClass);

        $blacklist = $this->sodiumAuth->manager()->getBlacklist();

        $this->assertInstanceOf(stdClass::class, $blacklist);
    }

    /** @test */
    public function it_should_set_the_request()
    {
        $request = Request::create('/foo', 'GET', ['token' => 'some.random.token']);

        $this->parser->shouldReceive('setRequest')->once()->with($request);
        $this->parser->shouldReceive('parseToken')->andReturn('some.random.token');

        $token = $this->sodiumAuth->setRequest($request)->getToken();

        $this->assertEquals('some.random.token', $token);
    }

    /** @test */
    public function it_should_unset_the_token()
    {
        $this->parser->shouldReceive('parseToken')->andThrow(new TokenException);
        $token = new Token('foo.bar.baz');
        $this->sodiumAuth->setToken($token);

        $this->assertSame($this->sodiumAuth->getToken(), $token);
        $this->sodiumAuth->unsetToken();
        $this->assertNull($this->sodiumAuth->getToken());
    }

    /** @test */
    public function it_should_get_the_manager_instance()
    {
        $manager = $this->sodiumAuth->manager();
        $this->assertInstanceOf(Manager::class, $manager);
    }

    /** @test */
    public function it_should_get_the_parser_instance()
    {
        $parser = $this->sodiumAuth->parser();
        $this->assertInstanceOf(Parser::class, $parser);
    }

    /** @test */
    public function it_should_get_a_claim_value()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->once()->with('sub')->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->assertSame($this->sodiumAuth->setToken('foo.bar.baz')->getClaim('sub'), 1);
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
