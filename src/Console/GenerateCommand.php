<?php

namespace Ns147\SodiumAuth\Console;

use Illuminate\Console\Command;

abstract class GenerateCommand extends Command
{

    /**
     * @param string $key
     * @return bool
     */
    final protected function confirmOverwrite(string $type, string $key, string $option): bool
    {
        if($this->laravel['config']['sodium'][$type][$key]) {
            return $option ? 'force' : $this->confirm(
                'Are you sure you want to override the '.$type.' '.$key.'?'
            );
        }
        return true;
    }

    /**
     * @param string $key
     * @param string $value
     * @return void
     */
    final protected function writeConfigurationValue(string $key, string $value)
    {
        $pattern = "/^$key=.*$/m";
        $line = $key . '=' . $value;

        $filePath = $this->laravel->basePath() . '/.env';
        $contents = file_get_contents($filePath);
        $updated = preg_match($pattern, $contents) ? preg_replace($pattern, $line, $contents) : $contents . "\n" . $line;

        file_put_contents($filePath, $updated);
    }
}
