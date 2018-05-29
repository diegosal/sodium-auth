<?php

namespace Ns147\SodiumAuth\Test\Claims;

use Mockery;
use Carbon\Carbon;
use Ns147\SodiumAuth\Claims\Expiration;
use Illuminate\Contracts\Support\Arrayable;
use Tests\TestCase;

class ClaimTest extends TestCase
{
    /**
     * @var \Ns147\SodiumAuth\Claims\Expiration
     */
    protected $claim;

    protected $testNowTimestamp;

    public function setUp()
    {
        parent::setUp();
        Carbon::setTestNow($now = Carbon::now());
        $this->testNowTimestamp = $now->getTimestamp();
        $this->claim = new Expiration($this->testNowTimestamp);
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
     * @expectedExceptionMessage Invalid value provided for claim [exp]
     */
    public function it_should_throw_an_exception_when_passing_an_invalid_value()
    {
        $this->claim->setValue('foo');
    }

    /** @test */
    public function it_should_convert_the_claim_to_an_array()
    {
        $this->assertSame(['exp' => $this->testNowTimestamp], $this->claim->toArray());
    }

    /** @test */
    public function it_should_get_the_claim_as_a_string()
    {
        $this->assertJsonStringEqualsJsonString((string) $this->claim, $this->claim->toJson());
    }

    /** @test */
    public function it_should_get_the_object_as_json()
    {
        $this->assertJsonStringEqualsJsonString(json_encode($this->claim), $this->claim->toJson());
    }

    /** @test */
    public function it_should_implement_arrayable()
    {
        $this->assertInstanceOf(Arrayable::class, $this->claim);
    }
}
