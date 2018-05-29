<?php

namespace Ns147\SodiumAuth\Test\Claims;

use Mockery;
use Carbon\Carbon;
use Ns147\SodiumAuth\Claims\IssuedAt;
use Tests\TestCase;

class IssuedAtTest extends TestCase
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
     * @expectedExceptionMessage Invalid value provided for claim [iat]
     */
    public function it_should_throw_an_exception_when_passing_a_future_timestamp()
    {
        new IssuedAt($this->testNowTimestamp + 3600);
    }
}
