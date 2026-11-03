<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Screens;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\ProfileChallenge;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Channels\DeliveryChannel;
use Nakipelo\Orchid2FA\Events\TwoFactorChallengeSent;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\InteractsWithChallenge;
use Nakipelo\Orchid2FA\Policy\TwoFactorPolicy;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TwoFactorManager;
use Orchid\Screen\Actions\Button;
use Orchid\Screen\Fields\Input;
use Orchid\Screen\Fields\Label;
use Orchid\Screen\Screen;
use Orchid\Support\Color;
use Orchid\Support\Facades\Layout;

/**
 * Two-factor settings of the signed-in user (route `Orchid::profileTwoFactorRoute()`, spec §4.7, §6).
 *
 * Enabling and disabling are confirmed with a code of the user's channel (spec 0.2 §4.5, §6.3; the
 * limits of the login apply). An enforced user cannot disable it: the button is hidden and the server refuses
 * both the code request and the confirmation.
 */
class TwoFactorProfileScreen extends Screen
{
    use InteractsWithChallenge;

    /**
     * `required`, `enabled` or `disabled`.
     */
    public string $status = 'disabled';

    public bool $confirmed = false;

    public string $destination = '';

    /**
     * The action awaiting the code (`enable` / `disable`), if any.
     */
    public ?string $pendingAction = null;

    public int $codeLength = 6;

    /**
     * @return array<string, mixed>
     */
    public function query(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges): iterable
    {
        $user = $this->currentUser();
        $status = $policy->status($user);
        $pending = ProfileChallenge::fromSession($request->session(), $user->getAuthIdentifier());
        $channel = $challenges->channelFor($user);

        return [
            'status' => $status,
            'confirmed' => $policy->isConfirmed($user),
            'destination' => $channel instanceof DeliveryChannel ? $channel->maskedDestination($user) : '',
            'pendingAction' => $pending !== null && $this->allows($status, $pending->action) ? $pending->action : null,
            'codeLength' => $channel->codeInput()->length,
        ];
    }

    public function name(): ?string
    {
        return $this->trans('profile.title');
    }

    public function description(): ?string
    {
        return $this->trans('profile.description');
    }

    /**
     * @return iterable<mixed>
     */
    public function layout(): iterable
    {
        $enable = $this->pendingAction === ProfileChallenge::ENABLE;

        return [
            Layout::block(Layout::rows([
                Label::make('two_factor_status')
                    ->title($this->trans('profile.status'))
                    ->value($this->trans('status.'.$this->status)),

                Label::make('two_factor_destination')
                    ->title($this->trans('profile.destination'))
                    ->value($this->destinationText()),
            ]))
                ->title($this->trans('profile.status_title'))
                ->description($this->trans('profile.status_description.'.$this->status))
                ->commands([
                    Button::make($this->trans('profile.enable'))
                        ->icon('bs.shield-check')
                        ->type(Color::PRIMARY)
                        ->novalidate()
                        ->method('sendEnableCode')
                        ->canSee($this->status === 'disabled' && $this->pendingAction === null),

                    Button::make($this->trans('profile.disable'))
                        ->icon('bs.shield-x')
                        ->type(Color::DANGER)
                        ->novalidate()
                        ->method('sendDisableCode')
                        ->canSee($this->status === 'enabled' && $this->pendingAction === null),
                ]),

            Layout::block(Layout::rows([
                Input::make('code')
                    ->title($this->trans('challenge.code'))
                    ->help($this->trans('challenge.sent_to', ['destination' => $this->destination]))
                    ->autocomplete('one-time-code')
                    ->inputmode('numeric')
                    ->pattern('\d{'.$this->codeLength.'}')
                    ->maxlength($this->codeLength)
                    ->required(),
            ]))
                ->title($this->trans($enable ? 'profile.confirm_enable' : 'profile.confirm_disable'))
                ->description($this->trans('profile.confirm_description'))
                ->commands([
                    Button::make($this->trans('profile.cancel'))
                        ->novalidate()
                        ->method('cancelCode'),

                    Button::make($this->trans('challenge.resend'))
                        ->novalidate()
                        ->method($enable ? 'sendEnableCode' : 'sendDisableCode'),

                    Button::make($this->trans('profile.confirm'))
                        ->icon('bs.check-circle')
                        ->type(Color::PRIMARY)
                        ->method($enable ? 'enable' : 'disable'),
                ])
                ->canSee($this->pendingAction !== null),

            Layout::block(Layout::rows([
                Label::make('trusted_devices')
                    ->value($this->trans('profile.trusted_text')),
            ]))
                ->title($this->trans('profile.trusted_title'))
                ->description($this->trans('profile.trusted_description'))
                ->commands([
                    Button::make($this->trans('profile.trusted_forget'))
                        ->icon('bs.box-arrow-right')
                        ->novalidate()
                        ->confirm($this->trans('profile.trusted_confirm'))
                        ->method('forgetTrustedDevices'),
                ]),
        ];
    }

    /**
     * "Enable": send a code to the current address (spec §4.7).
     */
    public function sendEnableCode(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges): void
    {
        $this->sendCode($request, $policy, $challenges, ProfileChallenge::ENABLE);
    }

    /**
     * "Disable": send a code to the current address; refused for an enforced user.
     */
    public function sendDisableCode(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges): void
    {
        $this->sendCode($request, $policy, $challenges, ProfileChallenge::DISABLE);
    }

    /**
     * @throws ValidationException
     */
    public function enable(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, TwoFactorManager $manager): void
    {
        $user = $this->confirmCode($request, $policy, $challenges, ProfileChallenge::ENABLE);

        if ($user !== null) {
            $manager->enable($user, $challenges->channelFor($user));
            Orchid::toast($this->trans('profile.enabled'), 'success');
        }
    }

    /**
     * @throws ValidationException
     */
    public function disable(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, TwoFactorManager $manager): void
    {
        $user = $this->confirmCode($request, $policy, $challenges, ProfileChallenge::DISABLE);

        if ($user !== null) {
            $manager->disable($user);
            Orchid::toast($this->trans('profile.disabled'), 'success');
        }
    }

    /**
     * Drop the code step. The sent code is not deleted (like "sign in as a different user").
     */
    public function cancelCode(Request $request): void
    {
        ProfileChallenge::forget($request->session());
    }

    /**
     * "Sign out of all trusted devices": available with any status (spec §4.7).
     */
    public function forgetTrustedDevices(TwoFactorManager $manager): void
    {
        $manager->forgetTrustedDevices($this->currentUser());

        Orchid::toast($this->trans('profile.trusted_forgotten'), 'success');
    }

    /**
     * @param  ProfileChallenge::ENABLE|ProfileChallenge::DISABLE  $action
     */
    protected function sendCode(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, string $action): void
    {
        $user = $this->currentUser();

        if (! $this->authorizeAction($request, $policy, $user, $action)) {
            return;
        }

        $channel = $challenges->channelFor($user);

        try {
            $challenge = $challenges->issue($user, $action === ProfileChallenge::ENABLE
                ? TwoFactorChallengeSent::CONTEXT_ENABLE
                : TwoFactorChallengeSent::CONTEXT_DISABLE, $channel);
        } catch (SendLimitExceededException $e) {
            Orchid::toast($this->sendLimitMessage($e->availableIn), 'warning');

            return;
        } catch (DeliveryFailedException) {
            Orchid::toast($this->trans('errors.delivery_failed'), 'error');

            return;
        }

        (new ProfileChallenge($user->getAuthIdentifier(), $action, $challenge->id, $challenge->channel))->store($request->session());

        Orchid::toast($this->trans('profile.code_sent', [
            'destination' => $channel instanceof DeliveryChannel ? $channel->maskedDestination($user) : '',
        ]));
    }

    /**
     * The user, when the code of the action's own challenge is correct; null otherwise
     * (with a toast). A wrong code throws a validation error on `code`.
     *
     * @param  ProfileChallenge::ENABLE|ProfileChallenge::DISABLE  $action
     *
     * @throws ValidationException
     */
    protected function confirmCode(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, string $action): ?Authenticatable
    {
        $user = $this->currentUser();

        if (! $this->authorizeAction($request, $policy, $user, $action)) {
            return null;
        }

        $request->validate(['code' => 'required|string|max:64']);

        $challenge = ProfileChallenge::fromSession($request->session(), $user->getAuthIdentifier());

        if ($challenge === null || $challenge->action !== $action) {
            Orchid::toast($this->trans('errors.code_expired'), 'error');

            return null;
        }

        $result = $challenges->verify($user, $challenge->challenge(), (string) $request->input('code'));

        if ($result === VerificationResult::Invalid) {
            throw ValidationException::withMessages([
                'code' => $this->trans('errors.invalid_code', [
                    'attempts' => $challenges->attemptsLeft($user, $challenge->challenge()),
                ]),
            ]);
        }

        ProfileChallenge::forget($request->session());

        if ($result !== VerificationResult::Passed) {
            Orchid::toast($this->trans('errors.code_expired'), 'error');

            return null;
        }

        return $user;
    }

    /**
     * Enabling is for a user with the status `disabled`, disabling for `enabled` (voluntary).
     * An enforced user is refused with 403 (spec §4.7); otherwise a stale request only gets a toast.
     *
     * @param  ProfileChallenge::ENABLE|ProfileChallenge::DISABLE  $action
     */
    protected function authorizeAction(Request $request, TwoFactorPolicy $policy, Authenticatable $user, string $action): bool
    {
        $status = $policy->status($user);

        if ($status === 'required') {
            ProfileChallenge::forget($request->session());

            abort(403, $this->trans('profile.enforced'));
        }

        if ($this->allows($status, $action)) {
            return true;
        }

        ProfileChallenge::forget($request->session());
        Orchid::toast($this->trans($action === ProfileChallenge::ENABLE ? 'profile.already_enabled' : 'profile.not_enabled'), 'warning');

        return false;
    }

    protected function allows(string $status, string $action): bool
    {
        return ($action === ProfileChallenge::ENABLE && $status === 'disabled')
            || ($action === ProfileChallenge::DISABLE && $status === 'enabled');
    }

    protected function destinationText(): string
    {
        if ($this->status === 'disabled') {
            return $this->destination;
        }

        return $this->trans($this->confirmed ? 'profile.confirmed' : 'profile.unconfirmed', [
            'destination' => $this->destination,
        ]);
    }

    protected function currentUser(): Authenticatable
    {
        $user = Orchid::guard()->user();

        abort_if($user === null, 403);

        return $user;
    }
}
