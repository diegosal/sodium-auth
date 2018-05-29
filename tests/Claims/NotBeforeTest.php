<?php

namespace Ns147\SodiumAuth\Test\Claims;

use Mockery;
use Carbon\Carbon;
use Ns147\SodiumAuth\Claims\NotBefore;
use Tests\TestCase;

class NotBeforeTest extends TestCase
{
    protected $testNowTimestamp;

    public function setUp()
    {
        parent::setUp();
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
     * @expectedException \Ns147\SodiumAuth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [nbf]
     */
    public function it_should_throw_an_exception_when_passing_a_future_timestamp()
    {
        new NotBefore($this->testNowTimestamp + 3600);
    }

    /**
     * @test
     * @expectedException \Ns147\SodiumAuth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [nbf]
     */
    public function it_should_throw_an_exception_when_passing_an_invalid_value()
    {
        new NotBefore('foo');
    }
}
