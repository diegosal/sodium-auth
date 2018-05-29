<?php

namespace Ns147\SodiumAuth\Test\Providers\Auth;

use Mockery;
use Carbon\Carbon;
use Illuminate\Contracts\Auth\Guard;
use Ns147\SodiumAuth\Providers\Auth\Illuminate as Auth;
use Tests\TestCase;

class IlluminateTest extends TestCase
{
    /**
     * @var \Mockery\MockInterface|\Illuminate\Contracts\Auth\Guard
     */
    protected $authManager;

    /**
     * @var \Ns147\SodiumAuth\Providers\Auth\Illuminate
     */
    protected $auth;

    protected $testNowTimestamp;

    public function setUp()
    {
        parent::setUp();

        $this->authManager = Mockery::mock(Guard::class);
        $this->auth = new Auth($this->authManager);
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
    public function it_should_return_true_if_credentials_are_valid()
    {
        $this->authManager->shouldReceive('once')->once()->with(['email' => 'foo@bar.com', 'password' => 'foobar'])->andReturn(true);
        $this->assertTrue($this->auth->byCredentials(['email' => 'foo@bar.com', 'password' => 'foobar']));
    }

    /** @test */
    public function it_should_return_true_if_user_is_found()
    {
        $this->authManager->shouldReceive('onceUsingId')->once()->with(123)->andReturn(true);
        $this->assertTrue($this->auth->byId(123));
    }

    /** @test */
    public function it_should_return_false_if_user_is_not_found()
    {
        $this->authManager->shouldReceive('onceUsingId')->once()->with(123)->andReturn(false);
        $this->assertFalse($this->auth->byId(123));
    }

    /** @test */
    public function it_should_return_the_currently_authenticated_user()
    {
        $this->authManager->shouldReceive('user')->once()->andReturn((object) ['id' => 1]);
        $this->assertSame($this->auth->user()->id, 1);
    }
}
