<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Testing\TestResponse;
use Nakipelo\Orchid2FA\Challenge\Context;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\UserMethod;
use Nakipelo\Orchid2FA\Models\TwoFactorAuthentication;
use Nakipelo\Orchid2FA\Tests\Fixtures\FakeVerifierChannel;
use Orchid\Alert\Toast;
use Workbench\App\Models\User;

uses(RefreshDatabase::class);

/**
 * Review of 0.2.0: enabling in the profile asks for the password and does not replace a leftover
 * binding of another channel (spec 0.2 §5.5); a method whose driver is gone refuses the changes
 * instead of an error page (§4.5 item 3); the actions of the screen are throttled (§6.4).
 */
beforeEach(function () {
    Notification::fake();
    tfUseFake();
});

/**
 * @param  array<string, mixed>  $data
 */
function phPost(string $method, array $data = []): TestResponse
{
    $url = route('platform.profile.two-factor');

    return test()->from($url)->post(route('platform.profile.two-factor', ['method' => $method]), $data);
}

function phRecord(User $user): ?TwoFactorAuthentication
{
    return TwoFactorAuthentication::query()->where('user_id', $user->id)->first();
}

it('asks for the current password to enable', function () {
    $user = tfUser();
    $this->actingAs($user);

    phPost('sendEnableCode');
    $this->get(route('platform.profile.two-factor'))->assertSee('autocomplete="current-password"', false);
    $code = tfLastCode();

    phPost('enable', ['code' => $code])->assertSessionHasErrors('password');
    expect(phRecord($user)?->enabled_at)->toBeNull();

    // A wrong password does not check (or consume) the code and counts as an attempt.
    phPost('enable', ['password' => 'wrong', 'code' => $code])
        ->assertSessionHasErrors(['password' => 'The password is incorrect. Attempts left: 4.']);
    expect(phRecord($user)?->enabled_at)->toBeNull();

    phPost('enable', ['password' => 'password', 'code' => $code])
        ->assertSessionHasNoErrors()
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Two-factor authentication is enabled.');
    expect(phRecord($user)->enabled_at)->not->toBeNull();
});

it('drops the enabling after five wrong passwords', function () {
    $user = tfUser();
    $this->actingAs($user);
    phPost('chooseChannel', ['channel' => 'fake']);
    $secret = (string) EnrollmentState::fromSession(session()->driver(), $user, 'fake', Context::ENABLE, 600)?->get('secret');

    foreach (range(1, 4) as $ignored) {
        phPost('enable', ['password' => 'wrong', 'code' => FakeVerifierChannel::codeFor($secret)])->assertSessionHasErrors('password');
    }

    phPost('enable', ['password' => 'wrong', 'code' => FakeVerifierChannel::codeFor($secret)])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');
    phPost('enable', ['password' => 'password', 'code' => FakeVerifierChannel::codeFor($secret)])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');

    expect(app(FakeVerifierChannel::class)->isAvailableFor($user))->toBeFalse()
        ->and(phRecord($user)?->enabled_at)->toBeNull();
});

it('enables a user without a method (not_enrolled) with the password', function () {
    tfUseFake(['fake']);
    $user = tfEnforcedUser();
    $this->actingAs($user);
    phPost('chooseChannel', ['channel' => 'fake']);
    $secret = (string) EnrollmentState::fromSession(session()->driver(), $user, 'fake', Context::ENABLE, 600)?->get('secret');

    phPost('enable', ['password' => 'wrong', 'code' => FakeVerifierChannel::codeFor($secret)])
        ->assertSessionHasErrors(['password' => 'The password is incorrect. Attempts left: 4.']);
    phPost('enable', ['password' => 'password', 'code' => FakeVerifierChannel::codeFor($secret)])->assertSessionHasNoErrors();

    expect(phRecord($user)->channel)->toBe('fake');
});

it('does not replace a leftover binding of another channel when enabling', function () {
    $user = tfUser();
    $secret = FakeVerifierChannel::enrollUser($user);
    // The binding stays after the "2FA required" permission was taken away: status `disabled`.
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'channel' => 'fake', 'confirmed_at' => now(), 'enabled_at' => null]);
    expect(app(ChannelRegistry::class)->methodFor($user)->state)->toBe(UserMethod::ACTIVE);
    $this->actingAs($user);

    // Only the own channel is offered.
    $this->get(route('platform.profile.two-factor'))
        ->assertOk()
        ->assertSee(route('platform.profile.two-factor', ['method' => 'sendEnableCode']), false)
        ->assertDontSee('E-mail');

    phPost('chooseChannel', ['channel' => 'email'])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'This method is not available.');
    phPost('enable', ['password' => 'password', 'code' => '123456'])
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'The code is no longer valid. Please request a new one.');

    expect(tfSentCodes())->toBe([])
        ->and(phRecord($user)->channel)->toBe('fake')
        ->and(phRecord($user)->enabled_at)->toBeNull()
        ->and(DB::table('two_factor_fake')->where('user_id', $user->id)->value('secret'))->toBe($secret);

    // Enabling the own channel is a new enrollment of it, with the password.
    phPost('chooseChannel', ['channel' => 'fake'])->assertSessionHasNoErrors();
    $new = (string) EnrollmentState::fromSession(session()->driver(), $user, 'fake', Context::ENABLE, 600)?->get('secret');
    phPost('enable', ['password' => 'password', 'code' => FakeVerifierChannel::codeFor($new)])->assertSessionHasNoErrors();

    expect(phRecord($user)->enabled_at)->not->toBeNull()
        ->and(DB::table('two_factor_fake')->where('user_id', $user->id)->value('secret'))->toBe($new);
});

it('refuses every change but enabling when the driver of the method is gone', function (string $method, array $data) {
    config(['orchid-2fa.channels.allowed' => ['email']]);
    $user = tfUser();
    TwoFactorAuthentication::query()->create(['user_id' => $user->id, 'channel' => 'gone', 'confirmed_at' => now(), 'enabled_at' => now()]);
    expect(app(ChannelRegistry::class)->methodFor($user)->state)->toBe(UserMethod::UNAVAILABLE);
    $this->actingAs($user);

    $this->get(route('platform.profile.two-factor'))->assertOk();
    phPost($method, $data)
        ->assertRedirect(route('platform.profile.two-factor'))
        ->assertSessionHas(Toast::SESSION_MESSAGE, 'Your sign-in method is not available. Please contact your administrator.');

    expect(phRecord($user)->channel)->toBe('gone')
        ->and(phRecord($user)->enabled_at)->not->toBeNull();
})->with([
    'disable' => ['sendDisableCode', []],
    'confirm disable' => ['disable', ['password' => 'password', 'code' => '123456']],
    'switch' => ['startSwitch', ['channel' => 'email']],
    'rebind' => ['startRebind', []],
    'regenerate' => ['startRegenerate', []],
]);

it('throttles the actions of the profile screen per user, not showing it', function () {
    $user = tfUser();
    $this->actingAs($user);

    foreach (range(1, 30) as $ignored) {
        phPost('cancelCode')->assertRedirect();
    }

    phPost('cancelCode')->assertStatus(429);
    $this->get(route('platform.profile.two-factor'))->assertOk();

    // Another user has its own counter.
    $this->actingAs(tfUser('other@example.com'));
    phPost('cancelCode')->assertRedirect();
});
