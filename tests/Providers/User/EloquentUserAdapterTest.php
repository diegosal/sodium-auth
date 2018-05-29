<?php

namespace Ns147\SodiumAuth\Test\Providers\User;

use Mockery;
use Ns147\SodiumAuth\Providers\User\EloquentUserAdapter;
use Tests\TestCase;

class EloquentUserAdapterTest extends TestCase
{
    public function setUp()
    {
        $this->builder = Mockery::mock('Illuminate\Database\Query\Builder');
        $this->model = Mockery::mock('Illuminate\Database\Eloquent\Model');
        $this->user = new EloquentUserAdapter($this->model);
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_return_the_user_if_found()
    {
        $this->builder->shouldReceive('first')->once()->withNoArgs()->andReturn((object) ['id' => 1]);
        $this->model->shouldReceive('where')->once()->with('foo', 'bar')->andReturn($this->builder);

        $user = $this->user->getBy('foo', 'bar');

        $this->assertEquals(1, $user->id);
    }
}
