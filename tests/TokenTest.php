<?php

namespace Ns147\SodiumAuth\Test;

use Mockery;
use Ns147\SodiumAuth\Token;
use Tests\TestCase;

class TokenTest extends TestCase
{
    /**
     * @var \Ns147\SodiumAuth\Token
     */
    protected $token;

    public function setUp()
    {
        parent::setUp();

        $this->token = new Token('foo.bar.baz');
    }

    public function tearDown()
    {
        Mockery::close();

        parent::tearDown();
    }

    /** @test */
    public function it_should_return_the_token_when_casting_to_a_string()
    {
        $this->assertEquals((string) $this->token, $this->token);
    }

    /** @test */
    public function it_should_return_the_token_when_calling_get_method()
    {
        $this->assertInternalType('string', $this->token->get());
    }
}
