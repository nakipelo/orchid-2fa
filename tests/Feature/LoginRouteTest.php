<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Nakipelo\Orchid2FA\Http\Controllers\LoginController;
use Nakipelo\Orchid2FA\Tests\TestCase;
use Orchid\Platform\Http\Controllers\LoginController as OrchidLoginController;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

/**
 * Spec §5.3, §10 "Маршруты (этап 1)", §11 stage 1.
 */
function assertLoginRoutes(TestCase $test): void
{
    $routes = Route::getRoutes();

    $auth = $routes->getByName('platform.login.auth');
    expect($auth)->not->toBeNull()
        ->and($auth->getActionName())->toBe(LoginController::class.'@login')
        ->and($auth->methods())->toContain('POST')
        ->and(route('platform.login.auth', absolute: false))->toBe('/admin/login');

    // The URI resolves to the package controller, not to Orchid's.
    $matched = $routes->match(Request::create('/admin/login', 'POST'));
    expect($matched->getActionName())->toBe(LoginController::class.'@login')
        ->and($matched->gatherMiddleware())->toContain('throttle:60,1');

    // GET platform.login stays with Orchid.
    expect($routes->getByName('platform.login')->getActionName())
        ->toBe(OrchidLoginController::class.'@showLoginForm');
}

function createAdmin(): User
{
    return User::query()->create([
        'name' => 'admin',
        'email' => 'admin@example.com',
        'password' => Hash::make('password'),
        'permissions' => ['platform.index' => true],
    ]);
}

function assertPostReachesPackageController(TestCase $test): void
{
    createAdmin();

    $test->post(route('platform.login.auth'), [
        'email' => 'admin@example.com',
        'password' => 'password',
    ])->assertRedirect(route('platform.main'));

    expect(app('router')->current()?->getActionName())->toBe(LoginController::class.'@login');
    $test->assertAuthenticated();

    // GET login is still served by Orchid.
    auth()->logout();
    $test->get(route('platform.login'))->assertOk()->assertSee('name="password"', false);
    expect(app('router')->current()?->getActionName())->toBe(OrchidLoginController::class.'@showLoginForm');
}

it('replaces Orchid POST login with the package controller', function () {
    expect($this->app->routesAreCached())->toBeFalse();

    assertLoginRoutes($this);
});

it('dispatches a real POST to the package controller', function () {
    assertPostReachesPackageController($this);
});

it('calls the package controller, not Orchid, on POST login', function () {
    $this->mock(LoginController::class)
        ->shouldReceive('login')->once()
        ->andReturn(response('package controller'));

    $this->post('/admin/login', ['email' => 'a@b.c', 'password' => 'x'])
        ->assertOk()
        ->assertSeeText('package controller');
});

it('keeps Orchid behaviour for wrong credentials', function () {
    createAdmin();

    $this->from(route('platform.login'))
        ->post(route('platform.login.auth'), ['email' => 'admin@example.com', 'password' => 'wrong'])
        ->assertRedirect(route('platform.login'))
        ->assertSessionHasErrors('email');

    $this->assertGuest();
});

it('keeps the replacement after route:cache', function () {
    // Runs `testbench route:cache` in a separate process against the workbench
    // application (testbench.yaml) and reloads the test application from the cache file.
    $this->defineCacheRoutes(<<<'PHP'
<?php
PHP);

    expect($this->app->routesAreCached())->toBeTrue()
        ->and(file_exists($this->app->getCachedRoutesPath()))->toBeTrue();

    assertLoginRoutes($this);
    assertPostReachesPackageController($this);

    // The profile screen of stage 4 is cached as well, with the methods of the screen.
    $profile = $this->app['router']->getRoutes()->getByName('platform.profile.two-factor');
    expect($profile)->not->toBeNull()
        ->and($profile->uri())->toBe('admin/profile/two-factor/{method?}')
        ->and($profile->wheres['method'] ?? '')->toContain('sendDisableCode');
});
