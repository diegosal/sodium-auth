<?php

namespace Ns147\SodiumAuth\Test;

use Mockery;
use Carbon\Carbon;
use Ns147\SodiumAuth\Payload;
use Ns147\SodiumAuth\Claims\Claim;
use Ns147\SodiumAuth\Claims\TokenId;
use Ns147\SodiumAuth\Claims\Issuer;
use Ns147\SodiumAuth\Claims\Subject;
use Ns147\SodiumAuth\Claims\Audience;
use Ns147\SodiumAuth\Claims\IssuedAt;
use Ns147\SodiumAuth\Claims\NotBefore;
use Ns147\SodiumAuth\Claims\Collection;
use Ns147\SodiumAuth\Claims\Expiration;
use Ns147\SodiumAuth\Validators\PayloadValidator;
use Tests\TestCase;

class PayloadTest extends TestCase
{
    /**
     * @var \Mockery\MockInterface|\Ns147\SodiumAuth\Validators\PayloadValidator
     */
    protected $validator;

    /**
     * @var \Ns147\SodiumAuth\Payload
     */
    protected $payload;

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
     * @expectedException \Ns147\SodiumAuth\Exceptions\PayloadException
     * @expectedExceptionMessage The payload is immutable
     */
    public function it_should_throw_an_exception_when_trying_to_add_to_the_payload()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $payload['foo'] = 'bar';
    }

    /**
     * @test
     * @expectedException \Ns147\SodiumAuth\Exceptions\PayloadException
     * @expectedExceptionMessage The payload is immutable
     */
    public function it_should_throw_an_exception_when_trying_to_remove_a_key_from_the_payload()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        unset($payload['foo']);
    }

    /** @test */
    public function it_should_cast_the_payload_to_a_string_as_json()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $this->assertSame((string) $payload, json_encode($payload->get(), JSON_UNESCAPED_SLASHES));
        $this->assertJsonStringEqualsJsonString((string) $payload, json_encode($payload->get()));
    }

    /** @test */
    public function it_should_allow_array_access_on_the_payload()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $this->assertTrue(isset($payload['iat']));
        $this->assertSame($payload['sub'], 1);
        $this->assertArrayHasKey('exp', $payload);
    }

    /** @test */
    public function it_should_get_properties_of_payload_via_get_method()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $this->assertInternalType('array', $payload->get());
        $this->assertSame($payload->get('sub'), 1);

        $this->assertSame(
            $payload->get(function () {
                return 'jti';
            }),
            'foo'
        );
    }

    /** @test */
    public function it_should_get_multiple_properties_when_passing_an_array_to_the_get_method()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $values = $payload->get(['sub', 'jti']);

        list($sub, $jti) = $values;

        $this->assertInternalType('array', $values);
        $this->assertSame($sub, 1);
        $this->assertSame($jti, 'foo');
    }

    /** @test */
    public function it_should_determine_whether_the_payload_has_a_claim()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $this->assertTrue($payload->has(new Subject(1)));
        $this->assertFalse($payload->has(new Audience(1)));
    }

    /** @test */
    public function it_should_magically_get_a_property()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);

        $sub = $payload->getSubject();
        $jti = $payload->getTokenId();
        $iss = $payload->getIssuer();

        $this->assertSame($sub, 1);
        $this->assertSame($jti, 'foo');
        $this->assertSame($iss, 'http://example.com');
    }

    /** @test */
    public function it_should_invoke_the_instance_as_a_callable()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);

        $sub = $payload('sub');
        $jti = $payload('jti');
        $iss = $payload('iss');

        $this->assertSame($sub, 1);
        $this->assertSame($jti, 'foo');
        $this->assertSame($iss, 'http://example.com');

        $this->assertSame($payload(), $payload->toArray());
    }

    /**
     * @test
     * @expectedException \BadMethodCallException
     * @expectedExceptionMessage The claim [getFoo] does not exist on the payload.
     */
    public function it_should_throw_an_exception_when_magically_getting_a_property_that_does_not_exist()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $payload->getFoo();
    }

    /** @test */
    public function it_should_get_the_claims()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $claims = $payload->getClaims();

        $this->assertInstanceOf(Expiration::class, $claims['exp']);
        $this->assertInstanceOf(TokenId::class, $claims['jti']);
        $this->assertInstanceOf(Subject::class, $claims['sub']);

        $this->assertContainsOnlyInstancesOf(Claim::class, $claims);
    }

    /** @test */
    public function it_should_get_the_object_as_json()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $this->assertJsonStringEqualsJsonString(json_encode($payload), $payload->toJson());
    }

    /** @test */
    public function it_should_count_the_claims()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $this->assertSame(6, $payload->count());
        $this->assertCount(6, $payload);
    }

    /** @test */
    public function it_should_match_values()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $values = $payload->toArray();
        $values['sub'] = (string) $values['sub'];

        $this->assertTrue($payload->matches($values));
    }

    /** @test */
    public function it_should_match_strict_values()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $values = $payload->toArray();

        $this->assertTrue($payload->matchesStrict($values));
        $this->assertTrue($payload->matches($values, true));
    }

    /** @test */
    public function it_should_not_match_empty_values()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $this->assertFalse($payload->matches([]));
    }

    /** @test */
    public function it_should_not_match_values()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $values = $payload->toArray();
        $values['sub'] = 'dummy_subject';

        $this->assertFalse($payload->matches($values));
    }

    /** @test */
    public function it_should_not_match_strict_values()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);
        $values = $payload->toArray();
        $values['sub'] = (string) $values['sub'];

        $this->assertFalse($payload->matchesStrict($values));
        $this->assertFalse($payload->matches($values, true));
    }

    /** @test */
    public function it_should_not_match_a_non_existing_claim()
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

        $this->validator = Mockery::mock(PayloadValidator::class);
        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);

        $payload = new Payload($collection, $this->validator);

        $values = ['foo' => 'bar'];

        $this->assertFalse($payload->matches($values));
    }

}
