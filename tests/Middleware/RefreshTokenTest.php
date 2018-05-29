<?php

namespace Ns147\SodiumAuth\Test\Middleware;

use Mockery;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Ns147\SodiumAuth\SAuth;
use Illuminate\Http\Response;
use Ns147\SodiumAuth\Http\Parser\Parser;
use Ns147\SodiumAuth\Http\Middleware\RefreshToken;
use Ns147\SodiumAuth\Exceptions\TokenInvalidException;
use Tests\TestCase;

class RefreshTokenTest extends TestCase
{
    /**
     * @var \Ns147\SodiumAuth\Http\Middleware\Check
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

        $this->middleware = new RefreshToken($this->auth);
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
    public function it_should_refresh_a_token()
    {
        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('hasToken')->once()->andReturn(true);

        $this->auth->shouldReceive('parser')->andReturn($parser);

        $this->auth->parser()->shouldReceive('setRequest')->once()->with($this->request)->andReturn($this->auth->parser());
        $this->auth->shouldReceive('parseToken->refresh')->once()->andReturn('foo.bar.baz');

        $response = $this->middleware->handle($this->request, function () {
            return new Response;
        });

        $this->assertSame($response->headers->get('authorization'), 'Bearer foo.bar.baz');
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
            //
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
        $this->auth->shouldReceive('parseToken->refresh')->once()->andThrow(new TokenInvalidException);

        $this->middleware->handle($this->request, function () {
            //
        });
    }
}
