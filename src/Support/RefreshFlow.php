<?php

namespace Ns147\SodiumAuth\Support;

trait RefreshFlow
{
    /**
     * The refresh flow flag.
     *
     * @var bool
     */
    protected $refreshFlow = false;

    /**
     * Set the refresh flow flag.
     *
     * @param  bool  $refreshFlow
     *
     * @return $this
     */
    public function setRefreshFlow($refreshFlow = true)
    {
        $this->refreshFlow = $refreshFlow;

        return $this;
    }
}
