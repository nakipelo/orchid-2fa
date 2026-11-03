<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Testing;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Events\RequestHandled;
use Illuminate\Foundation\Mix;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\HtmlString;
use Illuminate\Testing\TestResponse;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\VerifierChannel;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Orchid2FAServiceProvider;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\Testing\Concerns\TestsBypasses;
use Nakipelo\Orchid2FA\Testing\Concerns\TestsEnrollment;
use Nakipelo\Orchid2FA\Testing\Concerns\TestsLimits;
use Nakipelo\Orchid2FA\Testing\Concerns\TestsLogin;
use Nakipelo\Orchid2FA\Testing\Concerns\TestsRecoveryCodes;
use Nakipelo\Orchid2FA\Testing\Concerns\TestsRemember;
use Nakipelo\Orchid2FA\Testing\Concerns\TestsReset;
use Nakipelo\Orchid2FA\Testing\Concerns\TestsSecrets;
use Nakipelo\Orchid2FA\Testing\Concerns\TestsTrustedDevices;
use Nakipelo\Orchid2FA\Testing\Fixtures\User;
use Orchestra\Testbench\TestCase;
use Orchid\Platform\Dashboard;
use Orchid\Platform\Models\User as OrchidUser;
use Orchid\Platform\Providers\FoundationServiceProvider;
use Orchid\Support\Facades\Alert as AlertFacade;
use Orchid\Support\Facades\Dashboard as DashboardFacade;
use ReflectionClass;
use Symfony\Component\HttpFoundation\Response;

/**
 * The conformance suite of a two-factor channel (spec 0.2 §10.2): extend it in the tests of a
 * driver and implement the hooks. The suite boots Orchid, nakipelo/orchid-2fa and the driver's
 * providers on Testbench with an in-memory SQLite database and the fixture user model
 * Testing\Fixtures\User; the user of every test is enforced (the "2FA required" permission of Orchid)
 * and has the channel under test as the only allowed method.
 *
 * Requires orchestra/testbench and phpunit/phpunit (or Pest) in require-dev of the driver: this
 * package does not depend on them. A group that does not apply to the channel may be skipped by
 * overriding its test with `markTestSkipped()`; the groups skip on their own what cannot apply
 * (e.g. "send again" of a verifier channel).
 */
abstract class ChannelConformanceTestCase extends TestCase
{
    use TestsBypasses;
    use TestsEnrollment;
    use TestsLimits;
    use TestsLogin;
    use TestsRecoveryCodes;
    use TestsRemember;
    use TestsReset;
    use TestsSecrets;
    use TestsTrustedDevices;

    public const LOG_CHANNEL = 'orchid-2fa-conformance';

    public const PASSWORD = 'conformance-password';

    /**
     * The registry name of the channel under test.
     */
    abstract protected function channelName(): string;

    /**
     * Service providers of the driver (they register it with TwoFactor::extend()).
     *
     * @return list<class-string>
     */
    abstract protected function channelProviders(): array;

    /**
     * Bring the user to the enrolled state directly (e.g. insert a confirmed secret).
     */
    abstract protected function enroll(User $user): void;

    /**
     * A code the channel accepts for the user now. A delivery channel returns the code it has
     * just sent (the suite starts the challenge first).
     */
    abstract protected function validCode(User $user): string;

    /**
     * A code the channel refuses for the user now. `$state` is the enrollment step the code is for
     * (null — a code of the login or of the enrolled method): exclude the codes the step accepts too,
     * e.g. those of the secret in the state.
     */
    abstract protected function invalidCode(User $user, ?EnrollmentState $state = null): string;

    /**
     * Move to the next code window, so that validCode() returns a new code (a verifier channel
     * with time steps); a no-op for a delivery channel.
     */
    abstract protected function nextCodeWindow(): void;

    /**
     * The code that completes the enrollment step started with `$state`.
     */
    abstract protected function completeEnrollmentCode(User $user, EnrollmentState $state): string;

    /**
     * A second instance of the verifier channel under test that calls `$between` once in the middle
     * of its verification of a code: after it has read what decides whether the code may be accepted
     * (e.g. the last accepted time step) and before it writes the code as used. The suite verifies the
     * same code through the registry inside `$between`, i.e. a second request runs entirely between the
     * read and the write of the first, and exactly one of them must pass (spec 0.2 §4.2, §9 "Replay").
     *
     * The suite cannot reach inside verifyCode(), so a verifier driver must override it (with the
     * default null the test fails with "Override racingChannel() or skipsRaceTest()"): a subclass that
     * runs the callback at that point (here the driver reads the row in a method `matchingStep()` and
     * writes it right after), for example:
     *
     *     protected function racingChannel(Closure $between): ?VerifierChannel
     *     {
     *         $channel = new class extends MyChannel
     *         {
     *             public ?Closure $between = null;
     *
     *             protected function matchingStep(string $secret, string $code, ?int $lastStep): ?int
     *             {
     *                 $step = parent::matchingStep($secret, $code, $lastStep);
     *                 [$between, $this->between] = [$this->between, null];
     *
     *                 if ($between !== null) {
     *                     $between();
     *                 }
     *
     *                 return $step;
     *             }
     *         };
     *         $channel->between = $between;
     *
     *         return $channel;
     *     }
     *
     * The suite boots the returned channel with the name and config of the channel under test.
     * A delivery channel needs nothing: its verify() is the final one of DeliveryChannel, which
     * claims the code atomically.
     *
     * @param  Closure(): void  $between
     */
    protected function racingChannel(Closure $between): ?VerifierChannel
    {
        return null;
    }

    /**
     * An explicit opt-out of the race test for a verifier driver that cannot offer racingChannel()
     * (e.g. the read and the write are one statement of an external service): the test is skipped
     * instead of failing. The driver then has to prove the atomicity of its replay protection with
     * its own tests (spec 0.2 §9 "Replay").
     */
    protected function skipsRaceTest(): bool
    {
        return false;
    }

    protected function setUp(): void
    {
        parent::setUp();

        // Each request starts with an empty cookie queue, as in a fresh PHP process: the
        // application (and its CookieJar singleton) is shared by all requests of a test.
        $this->application()->make('events')->listen(RequestHandled::class, function (): void {
            $this->application()->make('cookie')->flushQueuedCookies();
        });
    }

    /**
     * The application of the test.
     */
    protected function application(): Application
    {
        return $this->app ?? throw new \LogicException('The application has not been created.');
    }

    /**
     * The channel under test.
     */
    protected function channel(): TwoFactorChannel
    {
        return $this->application()->make(ChannelRegistry::class)->channel($this->channelName());
    }

    protected function isDelivery(): bool
    {
        return $this->channel()->requiresDelivery();
    }

    /**
     * An enforced user whose method is the channel under test.
     */
    protected function enrolledUser(string $email = 'conformance@example.com'): User
    {
        $user = $this->makeUser($email);
        $this->enroll($user);

        TwoFactorAuthentication::query()->updateOrCreate(
            ['user_id' => $user->getKey()],
            ['channel' => $this->channelName(), 'confirmed_at' => now()],
        );

        return $user;
    }

    protected function makeUser(string $email = 'conformance@example.com'): User
    {
        $user = new User(['name' => 'conformance', 'email' => $email, 'password' => Hash::make(self::PASSWORD)]);
        $user->forceFill(['permissions' => [Orchid::requiredPermission() => true]])->save();

        return $user;
    }

    /**
     * The password step.
     *
     * @param  array<string, mixed>  $extra
     * @return TestResponse<Response>
     */
    protected function login(User $user, array $extra = []): TestResponse
    {
        return $this->post(Orchid::loginUrl(), ['email' => $user->email, 'password' => self::PASSWORD] + $extra);
    }

    /**
     * @param  array<string, mixed>  $extra
     * @return TestResponse<Response>
     */
    protected function verifyCode(string $code, array $extra = []): TestResponse
    {
        return $this->post(route(Orchid::verifyRoute()), ['code' => $code] + $extra);
    }

    protected function homeUrl(): string
    {
        return Orchid::indexUrl();
    }

    protected function challenges(): ChallengeManager
    {
        return $this->application()->make(ChallengeManager::class);
    }

    /**
     * Next requests come from a new browser: no cookies, no session, nobody signed in.
     */
    protected function newBrowser(): void
    {
        $this->defaultCookies = [];
        $this->unencryptedCookies = [];
        $this->flushSession();
        $this->application()->make('auth')->forgetGuards();
    }

    protected function logHandler(): TestHandler
    {
        /** @var \Illuminate\Log\Logger $logger */
        $logger = $this->application()->make('log')->channel(self::LOG_CHANNEL);
        $monolog = $logger->getLogger();

        foreach ($monolog instanceof Logger ? $monolog->getHandlers() : [] as $handler) {
            if ($handler instanceof TestHandler) {
                return $handler;
            }
        }

        throw new \RuntimeException('The conformance log channel has no TestHandler.');
    }

    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app)
    {
        // Orchid registers its own dependencies (breadcrumbs, icons, routes); package discovery is
        // not relied upon, so the suite works in a driver without a Testbench package manifest.
        return [FoundationServiceProvider::class, Orchid2FAServiceProvider::class, ...$this->channelProviders()];
    }

    /**
     * The aliases Orchid's views use (its composer `extra.laravel.aliases`).
     *
     * @param  Application  $app
     * @return array<string, class-string>
     */
    protected function getPackageAliases($app)
    {
        return ['Alert' => AlertFacade::class, 'Dashboard' => DashboardFacade::class];
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app)
    {
        // Orchid views call mix() for its published assets, which tests do not publish.
        $app->instance(Mix::class, static fn (): HtmlString => new HtmlString(''));

        tap($app['config'], function (Repository $config): void {
            $config->set('app.env', 'testing');
            $config->set('app.key', 'base64:'.base64_encode(str_repeat('c', 32)));
            $config->set('database.default', 'testing');
            $config->set('database.connections.testing', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true]);
            $config->set('hashing.bcrypt.rounds', 4);
            $config->set('cache.default', 'array');
            $config->set('session.driver', 'array');
            $config->set('mail.default', 'array');
            $config->set('auth.providers.users.model', User::class);
            $config->set('orchid-2fa.channels.allowed', [$this->channelName()]);
            $config->set('orchid-2fa.log.enabled', true);
            $config->set('logging.channels.'.self::LOG_CHANNEL, ['driver' => 'monolog', 'handler' => TestHandler::class]);
            $config->set('logging.default', self::LOG_CHANNEL);
        });

        Dashboard::useModel(OrchidUser::class, User::class);
        Orchid::useIndexRoute('orchid-2fa-conformance.home');
    }

    /**
     * @param  Router  $router
     */
    protected function defineRoutes($router)
    {
        Route::get('orchid-2fa-conformance/home', static fn (): string => 'home')
            ->middleware('web')
            ->name('orchid-2fa-conformance.home');
    }

    protected function defineDatabaseMigrations()
    {
        $this->loadLaravelMigrations();

        $dashboard = (new ReflectionClass(Dashboard::class))->getFileName();
        $this->loadMigrationsFrom(dirname((string) $dashboard, 3).'/database/migrations');

        // The package and the driver register their own migrations.
        $this->application()->make(Kernel::class)->call('migrate');
    }
}
