<?php

namespace Ns147\SodiumAuth\Console;

use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\KeyFactory;
use Illuminate\Support\Str;
use Illuminate\Console\Command;

class InstallCommand extends Command
{
    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = 'sodium:install
        {--path= : The path to save key outside webroot.}
        {--f|force : Skip confirmation when overwriting an existing key.}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'SodiumAuth install keys';

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        if ($this->input->hasOption('path') && $this->option('path')) {
            $this->call('sodium:encryptionkey', ['--path' => $this->option('path')]);
        }
        $this->call('sodium:generate:seal:pair', ['--force' => $this->option('force')]);
        $this->call('sodium:generate:shared:authentication', ['--force' => $this->option('force')]);
        $this->call('sodium:generate:shared:encryption', ['--force' => $this->option('force')]);
        $this->call('sodium:generate:sign:pair', ['--force' => $this->option('force')]);
    }
}
