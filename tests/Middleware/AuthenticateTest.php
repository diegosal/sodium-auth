<?php

namespace Ns147\SodiumAuth\Test\Middleware;

use Mockery;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Ns147\SodiumAuth\SAuth;
use Ns147\SodiumAuth\Http\Parser\Parser;
use Ns147\SodiumAuth\Http\Middleware\Authenticate;
use Ns147\SodiumAuth\Exceptions\TokenInvalidException;

use Ns147\SodiumAuth\Contracts\TokenSubject;
use Tests\TestCase;

class AuthenticateTest extends TestCase
{
    /**
     * @var \Ns147\SodiumAuth\Http\Middleware\Authenticate
     */
    protected $middleware;

    /**
     * @var \Mockery\MockInterface|\Ns147\SodiumAuth\SAuth
     */
    protected $auth;
    /**
     * @var \Mockery\MockInterface|\Illuminate\Http\Request
     */
    protected $request;

    protected $testNowTimestamp;

    public function setUp()
    {
        parent::setUp();

        $this->auth = Mockery::mock(SAuth::class);
        $this->request = Mockery::mock(Request::class);

        $this->middleware = new Authenticate($this->auth);
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
    public function it_should_authenticate_a_user()
    {
        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(true);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('parseToken->authenticate')->once()->andReturn(new UserStub);

        $this->middleware->handle($this->request, function () {
        });
    }

    /**
     * @test
     * @expectedException \Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException
     */
    public function it_should_throw_an_unauthorized_exception_if_token_not_provided()
    {
        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(false);

        $this->auth->shouldReceive('parser')->andReturn($parser);
        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());

        $this->middleware->handle($this->request, function () {
            throw new \Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException("UnauthorizedHttpException");
        });
    }

    /**
     * @test
     * @expectedException \Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException
     */
    public function it_should_throw_an_unauthorized_exception_if_token_invalid()
    {
        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(true);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('parseToken->authenticate')->once()->andThrow(new TokenInvalidException);

        $this->middleware->handle($this->request, function () {
            //
        });
    }

    /**
     * @test
     * @expectedException \Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException
     */
    public function it_should_throw_an_unauthorized_exception_if_user_not_found()
    {
        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(true);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('parseToken->authenticate')->once()->andReturn(false);

        $this->middleware->handle($this->request, function () {
            //
        });
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
