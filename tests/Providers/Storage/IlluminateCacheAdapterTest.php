<?php

namespace Ns147\SodiumAuth\Test\Providers\Storage;

use Mockery;
use Ns147\SodiumAuth\Providers\Storage\IlluminateCacheAdapter;
use Tests\TestCase;

class IlluminateCacheAdapterTest extends TestCase
{
    public function setUp()
    {
        $this->cache = Mockery::mock('Illuminate\Cache\CacheManager');
        $this->storage = new IlluminateCacheAdapter($this->cache);

        $this->cache->shouldReceive('tags')->andReturn(Mockery::self());
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_add_the_item_to_storage()
    {
        $this->cache->shouldReceive('tags->put')->with('foo', 'bar', 10);

        $this->storage->add('foo', 'bar', 10);
    }

    /** @test */
    public function it_should_check_if_the_item_exists_in_storage()
    {
        $this->cache->shouldReceive('tags->has')->with('foo')->andReturn(true);

        $this->assertTrue($this->storage->has('foo'));
    }

    /** @test */
    public function it_should_remove_the_item_from_storage()
    {
        $this->cache->shouldReceive('tags->forget')->with('foo')->andReturn(true);

        $this->assertTrue($this->storage->destroy('foo'));
    }

    /** @test */
    public function it_should_remove_all_items_from_storage()
    {
        $this->cache->shouldReceive('tags->flush')->withNoArgs();

        $this->storage->flush();
    }
}
