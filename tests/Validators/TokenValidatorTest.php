<?php

namespace Ns147\SodiumAuth\Test\Validators;

use Mockery;
use Carbon\Carbon;
use Ns147\SodiumAuth\Validators\TokenValidator;
use Tests\TestCase;

class TokenValidatorTest extends TestCase
{
    /**
     * @var \Ns147\SodiumAuth\Validators\TokenValidator
     */
    protected $validator;

    protected $testNowTimestamp;

    public function setUp()
    {
        parent::setUp();

        $this->validator = new TokenValidator;
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
    public function it_should_return_true_when_providing_a_well_formed_token()
    {
        $this->assertTrue($this->validator->isValid('one.two.three'));
    }

    public function dataProviderMalformedTokens()
    {
        return [
            ['one.two.'],
            ['.two.'],
            ['.two.three'],
            ['one..three'],
            ['..'],
            [' . . '],
            [' one . two . three '],
        ];
    }

    /**
     * @test
     * @dataProvider \Ns147\SodiumAuth\Test\Validators\TokenValidatorTest::dataProviderMalformedTokens
     * @expectedException \Ns147\SodiumAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Malformed token
     * @param  string  $token
     */
    public function it_should_return_false_when_providing_a_malformed_token($token)
    {
        $this->assertFalse($this->validator->isValid($token));
    }

    /**
     * @test
     * @dataProvider \Ns147\SodiumAuth\Test\Validators\TokenValidatorTest::dataProviderMalformedTokens
     *
     * @param  string  $token
     * @expectedException \Ns147\SodiumAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Malformed token
     */
    public function it_should_throw_an_exception_when_providing_a_malformed_token($token)
    {
        $this->validator->check($token);
    }

    public function dataProviderTokensWithWrongSegmentsNumber()
    {
        return [
            ['one.two'],
            ['one.two.three.four'],
            ['one.two.three.four.five'],
        ];
    }

    /**
     * @test
     * @dataProvider \Ns147\SodiumAuth\Test\Validators\TokenValidatorTest::dataProviderTokensWithWrongSegmentsNumber
     * @expectedException \Ns147\SodiumAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Wrong number of segments
     * @param  string  $token
     */
    public function it_should_return_false_when_providing_a_token_with_wrong_segments_number($token)
    {
        $this->assertFalse($this->validator->isValid($token));
    }

    /**
     * @test
     * @dataProvider \Ns147\SodiumAuth\Test\Validators\TokenValidatorTest::dataProviderTokensWithWrongSegmentsNumber
     *
     * @param  string  $token
     * @expectedException \Ns147\SodiumAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Wrong number of segments
     */
    public function it_should_throw_an_exception_when_providing_a_malformed_token_with_wrong_segments_number($token)
    {
        $this->validator->check($token);
    }
}
