<?php

namespace Ns147\SodiumAuth\Test\Claims;

use Mockery;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Ns147\SodiumAuth\Claims\Claim;
use Ns147\SodiumAuth\Claims\TokenId;
use Ns147\SodiumAuth\Claims\Custom;
use Ns147\SodiumAuth\Claims\Issuer;
use Ns147\SodiumAuth\Claims\Factory;
use Ns147\SodiumAuth\Claims\Subject;
use Ns147\SodiumAuth\Claims\IssuedAt;
use Ns147\SodiumAuth\Claims\NotBefore;
use Ns147\SodiumAuth\Claims\Expiration;
use Tests\TestCase;

class FactoryTest extends TestCase
{
    /**
     * @var \Ns147\SodiumAuth\Claims\Factory
     */
    protected $factory;

    protected $testNowTimestamp;

    public function setUp()
    {
        parent::setUp();

        $this->factory = new Factory(Request::create('/foo', 'GET'));
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
    public function it_should_set_the_request()
    {
        $factory = $this->factory->setRequest(Request::create('/bar', 'GET'));
        $this->assertInstanceOf(Factory::class, $factory);
    }

    /** @test */
    public function it_should_set_the_ttl()
    {
        $this->assertInstanceOf(Factory::class, $this->factory->setTTL(30));
    }

    /** @test */
    public function it_should_get_the_ttl()
    {
        $this->factory->setTTL($ttl = 30);
        $this->assertSame($ttl, $this->factory->getTTL());
    }

    /** @test */
    public function it_should_get_a_defined_claim_instance_when_passing_a_name_and_value()
    {
        $this->assertInstanceOf(Subject::class, $this->factory->get('sub', 1));
        $this->assertInstanceOf(Issuer::class, $this->factory->get('iss', 'http://example.com'));
        $this->assertInstanceOf(Expiration::class, $this->factory->get('exp', $this->testNowTimestamp + 3600));
        $this->assertInstanceOf(NotBefore::class, $this->factory->get('nbf', $this->testNowTimestamp));
        $this->assertInstanceOf(IssuedAt::class, $this->factory->get('iat', $this->testNowTimestamp));
        $this->assertInstanceOf(TokenId::class, $this->factory->get('jti', 'foo'));
    }

    /** @test */
    public function it_should_get_a_custom_claim_instance_when_passing_a_non_defined_name_and_value()
    {
        $this->assertInstanceOf(Custom::class, $this->factory->get('foo', ['bar']));
    }

    /** @test */
    public function it_should_make_a_claim_instance_with_a_value()
    {
        $iat = $this->factory->make('iat');
        $this->assertSame($iat->getValue(), $this->testNowTimestamp);
        $this->assertInstanceOf(IssuedAt::class, $iat);

        $nbf = $this->factory->make('nbf');
        $this->assertSame($nbf->getValue(), $this->testNowTimestamp);
        $this->assertInstanceOf(NotBefore::class, $nbf);

        $iss = $this->factory->make('iss');
        $this->assertSame($iss->getValue(), 'http://localhost/foo');
        $this->assertInstanceOf(Issuer::class, $iss);

        $exp = $this->factory->make('exp');
        $this->assertSame($exp->getValue(), $this->testNowTimestamp + 3600);
        $this->assertInstanceOf(Expiration::class, $exp);

        $jti = $this->factory->make('jti');
        $this->assertInstanceOf(TokenId::class, $jti);
    }

    /** @test */
    public function it_should_extend_claim_factory_to_add_a_custom_claim()
    {
        $this->factory->extend('foo', Foo::class);

        $this->assertInstanceOf(Foo::class, $this->factory->get('foo', 'bar'));
    }
}

class Foo extends Claim
{
    /**
     * {@inheritdoc}
     */
    protected $name = 'foo';
}
