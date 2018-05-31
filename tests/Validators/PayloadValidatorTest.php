<?php

namespace Ns147\SodiumAuth\Test\Validators;

use Mockery;
use Carbon\Carbon;
use Ns147\SodiumAuth\Claims\TokenId;
use Ns147\SodiumAuth\Claims\Issuer;
use Ns147\SodiumAuth\Claims\Subject;
use Ns147\SodiumAuth\Claims\IssuedAt;
use Ns147\SodiumAuth\Claims\NotBefore;
use Ns147\SodiumAuth\Claims\Collection;
use Ns147\SodiumAuth\Claims\Expiration;
use Ns147\SodiumAuth\Test\AbstractTestCase;
use Ns147\SodiumAuth\Validators\PayloadValidator;
use Tests\TestCase;

class PayloadValidatorTest extends TestCase
{
    /**
     * @var \Ns147\SodiumAuth\Validators\PayloadValidator
     */
    protected $validator;

    protected $testNowTimestamp;

    public function setUp()
    {
        parent::setUp();

        $this->validator = new PayloadValidator;
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
    public function it_should_return_true_when_providing_a_valid_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new TokenId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue($this->validator->isValid($collection));
    }

    /**
     * @test
     * @expectedException \Ns147\SodiumAuth\Exceptions\TokenExpiredException
     * @expectedExceptionMessage Token has expired
     */
    public function it_should_throw_an_exception_when_providing_an_expired_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 1440),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp - 3660),
            new TokenId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /**
     * @test
     * @expectedException \Ns147\SodiumAuth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [nbf]
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_nbf_claim()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 1440),
            new NotBefore($this->testNowTimestamp + 3660),
            new IssuedAt($this->testNowTimestamp - 3660),
            new TokenId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /**
     * @test
     * @expectedException \Ns147\SodiumAuth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [iat]
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_iat_claim()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 1440),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp + 3660),
            new TokenId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /**
     * @test
     * @expectedException \Ns147\SodiumAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Token payload does not contain the required claims
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_payload()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /**
     * @test
     * @expectedException \Ns147\SodiumAuth\Exceptions\InvalidClaimException
     * @expectedExceptionMessage Invalid value provided for claim [exp]
     */
    public function it_should_throw_an_exception_when_providing_an_invalid_expiry()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration('foo'),
            new NotBefore($this->testNowTimestamp - 3660),
            new IssuedAt($this->testNowTimestamp + 3660),
            new TokenId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->check($collection);
    }

    /** @test */
    public function it_should_set_the_required_claims()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue($this->validator->setRequiredClaims(['iss', 'sub'])->isValid($collection));
    }

    /** @test */
    public function it_should_check_the_token_in_the_refresh_context()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 1000),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp - 2600), // this is LESS than the refresh ttl at 1 hour
            new TokenId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue(
            $this->validator->setRefreshFlow()->setRefreshTTL(60)->isValid($collection)
        );
    }

    /** @test */
    public function it_should_return_true_if_the_refresh_ttl_is_null()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 1000),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp - 2600), // this is LESS than the refresh ttl at 1 hour
            new TokenId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->assertTrue(
            $this->validator->setRefreshFlow()->setRefreshTTL(null)->isValid($collection)
        );
    }

    /**
     * @test
     * @expectedException \Ns147\SodiumAuth\Exceptions\TokenExpiredException
     * @expectedExceptionMessage Token has expired and can no longer be refreshed
     */
    public function it_should_throw_an_exception_if_the_token_cannot_be_refreshed()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp - 5000), // this is MORE than the refresh ttl at 1 hour, so is invalid
            new TokenId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->setRefreshFlow()->setRefreshTTL(60)->check($collection);
    }
}
