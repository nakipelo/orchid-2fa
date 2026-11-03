<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Mix;
use Illuminate\Support\HtmlString;
use Illuminate\Testing\TestResponse;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase as Orchestra;
use Symfony\Component\HttpFoundation\Response;

/**
 * Real orchid/platform on the workbench application (testbench.yaml):
 * the package provider, Orchid stubs, SQLite in memory.
 */
abstract class TestCase extends Orchestra
{
    use WithWorkbench;

    public const LOG_CHANNEL = 'orchid-2fa-test';

    /**
     * Use composer package discovery like a real application (orchid/platform and its dependencies).
     */
    protected $enablesPackageDiscoveries = true;

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        // Orchid views call mix() for its published assets; tests do not publish them.
        // Bound here (not via withoutMix()) so it also applies after application reloads.
        $app->instance(Mix::class, static fn (): HtmlString => new HtmlString(''));

        tap($app['config'], function (Repository $config): void {
            $config->set('app.env', 'testing');
            $config->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
            $config->set('database.default', 'testing');
            $config->set('database.connections.testing.foreign_key_constraints', true);
            // Cheap hashing; the rehash tests hash with 4 rounds to make a rehash necessary.
            $config->set('hashing.bcrypt.rounds', 5);
            $config->set('cache.default', 'array');
            $config->set('session.driver', 'array');
            $config->set('mail.default', 'array');
            $config->set('logging.channels.'.self::LOG_CHANNEL, [
                'driver' => 'monolog',
                'handler' => TestHandler::class,
            ]);
            $config->set('logging.default', self::LOG_CHANNEL);
        });
    }

    /**
     * Each request starts with an empty cookie queue, as in a fresh PHP process: the
     * application (and its CookieJar singleton) is shared by all requests of a test.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  array<string, mixed>  $parameters
     * @param  array<string, mixed>  $cookies
     * @param  array<string, mixed>  $files
     * @param  array<string, mixed>  $server
     * @param  string|null  $content
     * @return TestResponse<Response>
     */
    public function call($method, $uri, $parameters = [], $cookies = [], $files = [], $server = [], $content = null)
    {
        $this->app['cookie']->flushQueuedCookies();

        return parent::call($method, $uri, $parameters, $cookies, $files, $server, $content);
    }

    /**
     * Next requests come from a new browser: no cookies, no session, no user in memory.
     */
    public function newBrowser(): void
    {
        $this->defaultCookies = [];
        $this->unencryptedCookies = [];
        $this->flushSession();
        $this->app['auth']->forgetGuards();
    }

    protected function logHandler(): TestHandler
    {
        /** @var \Illuminate\Log\Logger $logger */
        $logger = $this->app['log']->channel(self::LOG_CHANNEL);
        /** @var Logger $monolog */
        $monolog = $logger->getLogger();

        foreach ($monolog->getHandlers() as $handler) {
            if ($handler instanceof TestHandler) {
                return $handler;
            }
        }

        throw new \RuntimeException('TestHandler is not configured.');
    }
}
