# nakipelo/orchid-2fa — спецификация v0.2

Статус: черновик для согласования. Базис — `docs/SPEC.md` (0.1/0.1.1, действующее поведение) и код `main` на коммите `4cde2d4` (0.1.1). Ссылки вида «§4.2 SPEC» ведут в `docs/SPEC.md`; «§N» без пометки — в этот документ. Где поведение 0.1 не меняется, здесь только ссылка.

## 1. Цель и границы

Способы второго фактора выносятся в драйверы, чтобы основной пакет не разрастался под каждый способ. Первый внешний драйвер — TOTP (запрос пользователя: Google Authenticator вместо почты), пакет `nakipelo/orchid-2fa-totp` 0.1.0 в отдельном репозитории.

**В 0.2.0 (`nakipelo/orchid-2fa`):**

- новый контракт канала «канал сам выдаёт вызов и проверяет код» (ломающее изменение, раздел Upgrade 0.1→0.2);
- два базовых класса: `DeliveryChannel` (код генерирует и доставляет сервер) и `VerifierChannel` (код генерирует пользователь);
- реестр драйверов: конфиг `channels.<name>.driver` и `TwoFactor::extend()`;
- `EmailChannel` — драйвер на `DeliveryChannel`, по умолчанию, zero-config; для e-mail-пользователей поведение 0.1 не меняется;
- один активный способ на пользователя, `channels.allowed`, подключение (enrollment) в профиле и при входе, смена способа, перепривязка, выключение;
- резервные коды (для драйверов с `needsRecoveryCodes()`);
- лимиты для verifier-каналов (на pending, окно на пользователя, суточный потолок) и уведомление о подборе кода;
- текущий пароль для смены способа, выключения, перепривязки и перевыпуска резервных кодов;
- массовый сброс пользователей канала `orchid-2fa:reset --channel=<name>`;
- поле `channel` в событиях, события `TwoFactorChannelChanged`, `RecoveryCodeUsed`, `RecoveryCodesRegenerated`, уведомление безопасности;
- точки расширения UI для драйвера;
- набор тестов соответствия `Nakipelo\Orchid2FA\Testing` и драйвер-заглушка в тестах пакета.

**Вне 0.2:** требование конкретного способа по праву (только `channels.allowed`; `platform.2fa.required` решает лишь, нужна ли 2FA); несколько активных способов одновременно; WebAuthn, SMS, Telegram (контракт их допускает, но драйверов нет); JSON-API для enrollment и показа резервных кодов (§6.4); отдельный Orchid-Layout драйвера (§6.1); самостоятельное восстановление без резервных кодов; поддержка следующего мажора Orchid. Middleware «залогинен, но 2FA в этой сессии не пройдена» (§1, §5.4, §9 SPEC называли его кандидатом на v0.2) переносится в 0.3; формулировки SPEC.md правятся на этапе 4 (§12).

## 2. Что не меняется

Поведение ниже действует для всех каналов и в 0.2 не пересказывается:

| Что | Где |
|---|---|
| Первичная аутентификация `validate()`, `Attempting`/`Failed`, rehash | §4.1 SPEC |
| Финальный вход, lock-cookie, `redirect()->intended()`, JSON `204` | §4.3 SPEC |
| Доверенное устройство: cookie, проверка, атрибуты, `trusted_devices.enabled` | §4.4, §5.6 SPEC |
| Remember: выдача только после 2FA, ротация при `confirmed_at = null`, `forgetConfirmation()` при входе без 2FA, `orchid-2fa:rotate-remember-tokens` | §4.5 SPEC |
| Impersonation | §4.6 SPEC |
| Отпечаток пароля в pending, «пароль изменён» | §3, §4.2 п. 5 SPEC |
| Fail-closed при ошибке доставки | §4.10 SPEC |
| Лимиты delivery-каналов (код, cooldown, час, throttle по IP) | §4.11, §5.9 SPEC |
| Адаптер `Support\Orchid`, правило `bin/check-adapter.php` | §5.1 SPEC (расширение — §4.9) |
| Замещение `POST login`, `platform.auth = false` | §5.3 SPEC |
| Права `platform.2fa.required`, `platform.systems.users.2fa-reset` | §8 SPEC |
| Пакет, окружение, матрица CI | §2 SPEC |

Для пользователя с каналом `email` (все пользователи после обновления с 0.1) сценарии §4.1–§4.11 SPEC остаются в силе дословно, кроме новых возможностей профиля (§5.6–§5.9), `channel` в событиях и одного изменения: выключение 2FA в профиле (§4.7 SPEC) требует текущий пароль вместе с кодом (§5.8).

## 3. Термины

Термины §3 SPEC действуют. Уточнения и новые:

- **Канал (драйвер)** — реализация `Contracts\TwoFactorChannel`, наследник `DeliveryChannel` или `VerifierChannel`. **Имя канала** — ключ реестра (`email`, `totp`), хранится в `two_factor_authentications.channel`.
- **Delivery-канал** — код генерирует сервер и доставляет (`email`, в будущем SMS, Telegram).
- **Verifier-канал** — код генерирует пользователь (TOTP, в будущем WebAuthn); сервер только проверяет.
- **Зарегистрированные каналы** — известные реестру (`channels.<name>.driver` или `TwoFactor::extend()`).
- **Разрешённые каналы** — зарегистрированные ∩ `channels.allowed`.
- **Подключённый способ** — `record.channel` не null, канал зарегистрирован и `isAvailableFor($user)` = true (email: адрес есть; TOTP: подтверждённый секрет).
- **Действующий способ** — подключённый и разрешённый способ пользователя, иначе канал по умолчанию (`channel`, если он разрешён и delivery), иначе нет (§4.5).
- **Вызов (challenge)** — value-object `Challenge` (§4.1): id, канал, контекст. Для delivery — выпущенный и отправленный код (как §3 SPEC), для verifier — только id, без побочных эффектов.
- **Enrollment (подключение)** — привязка способа: для verifier — секрет/устройство + первый верный код; для delivery без собственного состояния (email) — код на адрес (как включение в §4.7 SPEC).
- **Перепривязка** — повторный enrollment того же канала (новый телефон).
- **`confirmed_at`** сохраняет смысл 0.1: «после последнего события, которое могло выдать remember-cookie без второго фактора, второй фактор пройден» (якорь ротации remember §4.5 SPEC и условие cookie доверия §5.6 SPEC). Это **не** флаг «способ подключён»: подключённость verifier-канала хранит драйвер (TOTP: `two_factor_totp.confirmed_at`). Вход без 2FA обнуляет `confirmed_at`, но TOTP остаётся подключённым.
- **Резервный код** — одноразовый код `xxxx-xxxx` основного пакета (§4.7).
- **Подтверждение текущим способом** — верный код действующего способа (или резервный код там, где это разрешено: смена, перепривязка, выключение; не перевыпуск) **вместе с текущим паролем в той же форме**, полученные в этой сессии не раньше `profile.confirmation_ttl` назад (§5.6–§5.9).

## 4. Архитектура драйверов

### 4.1. Контракт `Contracts\TwoFactorChannel`

Заменяет интерфейс 0.1 (§5.2 SPEC). Удалены как обязательные: `destination()`, `maskedDestination()`, `send()` (переехали в `DeliveryChannel`). Сохранены: `name()`, `isAvailableFor()`.

```php
namespace Nakipelo\Orchid2FA\Contracts;

interface TwoFactorChannel
{
    public function name(): string;                                    // ключ реестра: 'email', 'totp'
    public function label(): string;                                   // переведённое имя для UI: «Почта», «Приложение-аутентификатор»
    public function requiresDelivery(): bool;                          // final в базовых классах
    public function needsRecoveryCodes(): bool;                        // email: false; TOTP: true
    public function isAvailableFor(Authenticatable $user): bool;       // способ подключён и может обслужить пользователя сейчас

    /** Выдать вызов. Delivery: лимиты, код, отправка; verifier: только id. */
    public function issue(Authenticatable $user, string $context): Challenge;   // throws SendLimitExceededException, DeliveryFailedException

    /** Проверить код вызова. Попытки уже засчитаны оркестратором (§4.4). */
    public function verify(Authenticatable $user, Challenge $challenge, string $code): VerificationResult;

    public function prompt(Authenticatable $user): string;             // строка экрана кода: «Код отправлен на e***@…» / «Введите код из приложения»
    public function codeInput(): CodeInput;                            // атрибуты поля кода
    public function challengeView(): ?string;                          // свой partial экрана кода или null — общий (§6.2)

    // Enrollment (§4.6)
    public function startEnrollment(Authenticatable $user, EnrollmentState $state): void;
    public function confirmEnrollment(Authenticatable $user, EnrollmentState $state, string $code): VerificationResult;
    public function enrollmentView(): ?string;                         // partial шага подключения или null
    /** @return array<string, mixed> */
    public function enrollmentData(Authenticatable $user, EnrollmentState $state): array;

    /** Хук сброса: стереть данные драйвера пользователя. Идемпотентен. */
    public function forget(Authenticatable $user): void;
}
```

Value-objects (публичный API, `Nakipelo\Orchid2FA\Challenge\`):

- `Challenge` (final, readonly): `string $id` (`Str::random(40)`), `string $channel`, `string $context`, `?int $expiresAt` (delivery — срок кода; verifier — null).
- `VerificationResult` (существующий enum, §5 SPEC): `Passed`, `Invalid`, `Expired`, `LockedOut`. Повтор кода (replay) — `Invalid`.
- `CodeInput` (final, readonly): `int $length`, `string $pattern`, `string $inputmode` (`numeric`), `string $autocomplete` (`one-time-code`).
- `EnrollmentState` — сессионное хранилище шага подключения (`orchid-2fa.enrollment`), привязано к `user_id`, каналу и контексту, живёт `enrollment_ttl` (при входе, §5.4) или `profile.confirmation_ttl` (в профиле): `get(string $key)`, `put(string $key, mixed $value)`, `challengeId(): string`. Секреты, которые драйвер кладёт сюда, хранятся в серверной сессии и стираются при завершении/отмене.

Контексты (`TwoFactorChallengeSent::CONTEXT_*` и `Challenge::$context`): `login`, `enable`, `disable` (0.1) + `switch`, `rebind`, `regenerate`, `enroll`, `fallback`.

### 4.2. Базовые классы `Channels\DeliveryChannel` и `Channels\VerifierChannel`

Оба абстрактные, реализуют `TwoFactorChannel`, своего конструктора не имеют (конструктор драйвера свободен для DI). Реестр после создания вызывает `final public function bootChannel(string $name, array $config): void` — имя и конфиг канала; общие сервисы базовые классы берут из контейнера. `requiresDelivery()` — `final`. Реестр принимает только наследников одного из двух классов (`InvalidArgumentException` иначе): тип канала нельзя «объявить» флагом.

**`DeliveryChannel`** — переносит логику `ChallengeManager::issue()/verify()/activeChallenge()/sendAvailableIn()` 0.1 без изменения поведения (§4.2, §4.10, §4.11, §5.9 SPEC):

| Метод | Кто | Поведение |
|---|---|---|
| `destination(Authenticatable): string` | драйвер, abstract | сырой адрес, к которому привязан код (`destination_hash`) |
| `send(Authenticatable, string $code, CarbonInterface $expiresAt): void` | драйвер, abstract | доставка; ошибка — `DeliveryFailedException` |
| `maskedDestination(Authenticatable): string` | база, переопределяемо | по умолчанию — маска `EmailChannel::mask()` |
| `issue()` | база, `final` | cooldown и часовой лимит, `random_int`, `CodeStore`, `send()`, fail-closed (код удаляется) |
| `verify()` | база, `final` | `challenge_id`, `destination_hash`, `hash_equals`, атомарный `claim` |
| `activeChallenge(Authenticatable): ?Challenge` | база | переиспользование активного кода (§4.2 п. 3 SPEC) |
| `sendAvailableIn(Authenticatable): int` | база | обратный отсчёт |
| `annul(Authenticatable)`, `forget(Authenticatable)` | база | аннулировать код; `forget` — код и счётчики (`ChallengeManager::clear()` 0.1) |
| `isAvailableFor()` | база | `destination() !== ''` |
| `needsRecoveryCodes()` | база | `false` |
| `prompt()`, `codeInput()` | база | `challenge.sent_to` с маской; `code.length` цифр |
| `startEnrollment()` / `confirmEnrollment()` | база | `issue(…, 'enroll')`, id в `EnrollmentState`; `verify()` |
| `enrollmentView()` | база | `null` (у email нет шага, кроме кода); драйвер с вводом адреса (SMS) переопределяет |

Ключи `CodeStore` и `RateLimiter` не меняются (`orchid-2fa:code:{uid}`, `orchid-2fa:send:{uid}`, `orchid-2fa:cooldown:{uid}`): у пользователя один активный способ, коллизий delivery-каналов нет. `CodeStore`, `StoredCode` остаются `@internal`.

**`VerifierChannel`**:

| Метод | Кто | Поведение |
|---|---|---|
| `verifyCode(Authenticatable, string $code): bool` | драйвер, abstract, protected | проверка кода; **обязана** включать защиту от повтора и быть атомарной при параллельных запросах |
| `isAvailableFor()` | драйвер, abstract | способ подключён (подтверждённый секрет) |
| `startEnrollment()`, `confirmEnrollment()`, `enrollmentView()`, `enrollmentData()` | драйвер, abstract | §4.6; `confirmEnrollment` сохраняет данные драйвера только при верном коде |
| `forget()` | драйвер, abstract | стереть данные драйвера |
| `issue()` | база, `final` | `Challenge` с новым id, без побочных эффектов и событий |
| `verify()` | база, `final` | нормализация (пробелы, дефисы), `verifyCode()`; исключение драйвера → лог `error` + `Invalid` (fail-closed) |
| `needsRecoveryCodes()` | база | `true` (переопределяемо) |
| `allowsEmailFallback(Authenticatable): bool` | база | `false`; TOTP — по своему конфигу (§13) |
| `prompt()`, `codeInput()` | база | `challenge.app_prompt`; 6 цифр, переопределяемо |

### 4.3. Реестр

`Channels\ChannelRegistry` (singleton) + фасад `Facades\TwoFactor`:

```php
TwoFactor::extend(string $name, Closure $factory): void;   // $factory(Container $app, array $config): TwoFactorChannel
TwoFactor::channel(string $name): TwoFactorChannel;        // создаётся лениво, кешируется; неизвестное имя — UnknownChannelException
TwoFactor::has(string $name): bool;
TwoFactor::registered(): array;                            // list<string>
TwoFactor::allowed(): array;                               // registered ∩ channels.allowed, в порядке channels.allowed
TwoFactor::for(Authenticatable $user): ?TwoFactorChannel;  // действующий способ (§4.5)
```

Разрешение имени: `channels.<name>.driver` задан → это имя из `extend()` или class-string наследника базового класса (создаётся контейнером); не задан → фабрика из `extend($name)`; иначе канала нет. Конфиг канала, передаваемый фабрике и в `bootChannel()`, — `config('orchid-2fa.channels.<name>', [])`. `channels.email.driver` по умолчанию — `EmailChannel::class`. Ключ 0.1 `channels.<name>.class` читается как `driver`, если `driver` не задан (совместимость с опубликованным конфигом 0.1, deprecated, удаляется в 0.3).

Драйвер регистрируется в `boot()` своего провайдера (`TwoFactor::extend('totp', …)`); собственный конфиг держит в своём файле (`config/orchid-2fa-totp.php`), а не в `orchid-2fa.channels.totp`: `mergeConfigFrom` сливает только верхний уровень, и опубликованный `orchid-2fa.php` затёр бы `channels` драйвера.

**Неизвестные имена в `channels.allowed`:**

- имя без драйвера игнорируется; в `local`/`testing` — `warning` в лог один раз за загрузку (как предупреждения §5.3 SPEC и о трейте); в остальных окружениях — молча;
- `php artisan about` получает раздел «Orchid 2FA»: зарегистрированные, разрешённые и проигнорированные имена;
- строгая ошибка — только когда разрешённых каналов не осталось: `InvalidArgumentException` в `booted` в `local`/`testing`; в остальных окружениях — лог `critical` и fail-closed при входе пользователя, которому нужна 2FA (вход по паролю без 2FA для остальных работает).

Обоснование: умолчание `['email', 'totp']` содержит необязательный драйвер, поэтому «нет драйвера» — штатная ситуация, а не ошибка; строгая ошибка на загрузке в проде положила бы всю админку из-за опечатки в списке, тогда как пустой список — реальная поломка (никто с 2FA не войдёт), и её надо поймать в разработке. Опечатку видно в логе `local` и в `about`.

### 4.4. Оркестратор `Challenge\ChallengeManager`

Остаётся точкой входа контроллеров и экрана профиля; генерация, хранение и отправка кода уходят в `DeliveryChannel`. Оркестратор, а не драйвер, отвечает за всё, что должно быть верно для любого канала:

- выбор канала: `TwoFactor::for($user)`; вызов, выданный для другого канала (способ сменился или сброшен во время pending), — `Expired`;
- **учёт попыток до вызова драйвера**: `orchid-2fa:verify:{uid}:{challenge_id}` (`code.max_attempts`, 5) для всех каналов; для verifier-каналов, резервных кодов (любого канала) и подтверждения enrollment verifier-канала ещё два счётчика на пользователя: окно `orchid-2fa:verifier:{uid}` (`verify.user_max_attempts` = 10 за `verify.user_decay` = 600 с) и суточный потолок `orchid-2fa:verifier-day:{uid}` (`verify.user_max_per_day` = 30 за 24 ч, окно фиксировано). Инкремент всех применимых счётчиков — до сравнения; драйвер не вызывается, если исчерпан любой;
- исчерпание per-challenge: delivery — код аннулируется, pending остаётся (как 0.1); verifier — pending удаляется, редирект на логин с `errors.too_many_attempts`;
- исчерпание окна на пользователя — `LockedOut`, `TwoFactorLockedOut(reason: user_attempts_exceeded, availableIn)`, pending сохраняется; суточного потолка — то же с `reason: user_daily_attempts_exceeded` и `errors.too_many_attempts_today` («попробуйте через N ч»). Отдельного события нет: потолок — тот же класс блокировки, различается причиной;
- **сигнал о подборе:** в момент исчерпания окна или суточного потолка оркестратор отправляет уведомление безопасности `attempts_exceeded` (§8.3) — «кто-то ввёл ваш пароль и подбирает код»; не чаще раза за `verify.user_decay` на пользователя (маркер `orchid-2fa:alert:{uid}`), отключается `notification.security.enabled`;
- все события (`TwoFactorChallengeSent`, `TwoFactorFailed`, `TwoFactorLockedOut`) порождает оркестратор, а не драйвер; исключения `issue()` не из числа `SendLimitExceededException`/`DeliveryFailedException` трактуются как `DeliveryFailedException` (fail-closed, лог `error`);
- резервные коды: `verifyRecoveryCode(Authenticatable, Challenge, string): VerificationResult` (§4.7).

Публичные методы: `start(Authenticatable $user, string $context, ?TwoFactorChannel $channel = null): Challenge`, `verify(Authenticatable, Challenge, string): VerificationResult`, `verifyRecoveryCode(…)`, `attemptsLeft(Authenticatable, Challenge): int` (минимум из применимых счётчиков), `sendAvailableIn(Authenticatable): int` (0 для verifier), `activeChallenge(Authenticatable): ?Challenge` (только delivery), `clear(Authenticatable)` (код, все счётчики, включая окно, суточный потолок и маркер уведомления). `channel()` 0.1 удаляется (был глобальным по `config('orchid-2fa.channel')` и игнорировал `record.channel`).

### 4.5. Действующий способ пользователя

`TwoFactor::for($user)`:

1. `record.channel` задан, канал зарегистрирован, разрешён и `isAvailableFor` — он.
2. `record.channel` задан, зарегистрирован и подключён, но **не разрешён** (администратор убрал из `channels.allowed`) — он используется для входа как доказательство, после верного кода следует обязательный enrollment разрешённого способа (§5.4, вариант Б). Это же — путь массового перевода пользователей одной строкой конфига (§11).
3. `record.channel` задан, но **драйвер не зарегистрирован** (пакет удалён) — fail-closed: вход не выполняется, `TwoFactorFailed(reason: channel_unavailable)`, лог `error`, сообщение «способ входа недоступен, обратитесь к администратору». Восстановление — сброс администратором, для всех пользователей канала сразу — `orchid-2fa:reset --channel=<name>` (§5.10). Тихого понижения до email нет.
4. Записи нет, `channel = null` или способ не подключён: канал по умолчанию `channel` (`'email'`), если он разрешён и это delivery-канал без шага enrollment, — он (поведение 0.1); иначе действующего способа нет → enrollment при входе (§5.4).

`TwoFactorPolicy` (`requires`, `isEnforced`, `isEnabled`) не меняется; добавляется `channel(Authenticatable): ?string` (имя действующего способа) и статус `not_enrolled` для UI (требуется, но способа нет).

Все места 0.1.1, где способ брался из глобального `config('orchid-2fa.channel')`, переводятся на способ пользователя на этапе 1 (§12): выбор канала при входе (`ChallengeManager::channel()`), `addressChanged()` (обнулял `confirmed_at` у записи любого канала, §5.11), маска адреса в `TwoFactorResetLayout` и экране профиля (§6.3). Иного смысла у `channel` в 0.1 не было: это канал по умолчанию.

### 4.6. Жизненный цикл вызова

**Delivery (email):** `start()` → `activeChallenge()` или `issue()` (лимиты, код, `send()`) → `TwoFactorChallengeSent` → pending с `Challenge` → `verify()`: per-challenge счётчик → `DeliveryChannel::verify()` → `Passed` / `Invalid` / `Expired` / `LockedOut`. Поведение §4.2, §5.9 SPEC.

**Verifier (TOTP):** `start()` → `VerifierChannel::issue()` (только id; `TwoFactorChallengeSent` **не** порождается — ничего не отправлено) → pending → `verify()`: per-challenge, окно на пользователя и суточный потолок (инкремент до сравнения) → `verifyCode()` (с защитой от повтора) → результат. «Отправить повторно» нет. Новый вход по паролю — новый id и новый per-challenge счётчик, но счётчики на пользователя общие: смена pending не даёт бесконечного перебора.

**Enrollment:** `EnrollmentState` создаётся с новым id → `startEnrollment()` (TOTP: секрет в state; email: код на адрес) → UI (`enrollmentView` + общее поле кода) → `confirmEnrollment()` под теми же счётчиками (verifier — оба; delivery — per-challenge и лимиты отправки) → при `Passed` `TwoFactorManager::commitEnrollment()` (§4.8).

### 4.7. Резервные коды

Сервис `Recovery\RecoveryCodes`, модель `Models\TwoFactorRecoveryCode`, таблица `two_factor_recovery_codes`. Включаются, только если `needsRecoveryCodes()` действующего способа.

- 8 кодов (`recovery_codes.count`), формат `xxxx-xxxx`, алфавит `23456789abcdefghjkmnpqrstuvwxyz` (без `0/o/1/l/i`), `random_int`; ввод без учёта регистра, пробелы и дефис игнорируются.
- Хранятся только хеши `Hash::make()` (хешер приложения), сравнение `Hash::check()` по неиспользованным кодам пользователя (до 8 проверок хешера на попытку, ограничено лимитами §4.4). Не HMAC на `app.key`: ротация ключа не должна уничтожать путь восстановления.
- Погашение атомарно: `UPDATE … SET used_at = now() WHERE id = ? AND used_at IS NULL`, успех — только при 1 затронутой строке.
- Новый набор выпускается при каждом успешном enrollment канала с `needsRecoveryCodes()` (подключение, смена на него, перепривязка) и при «Перевыпустить» в профиле; старый набор удаляется. Переход на канал без резервных кодов (email), выключение и сброс удаляют коды.
- Показ один раз: открытым текстом только в сессии (`orchid-2fa.recovery_codes`) до подтверждения «Я сохранил коды»; в БД, логах, событиях открытого текста нет.
- Где резервный код принимается: вход (§5.3), смена способа (§5.6), перепривязка (§5.7), выключение (§5.8). Перевыпуск — только кодом текущего способа (не резервным). В профиле — всегда вместе с текущим паролем.
- Попытки резервного кода считаются в per-challenge, окне на пользователя и суточном потолке (§4.4); неверный — `TwoFactorFailed(reason: invalid_recovery_code)`.
- Вход по резервному коду не выдаёт cookie доверия (§5.3).
- Профиль предупреждает при остатке ≤ `recovery_codes.warn_at` (2). Кодов нет и устройства нет — только сброс администратором (README).

### 4.8. `TwoFactorManager`

| 0.1 | 0.2 |
|---|---|
| `enable(Authenticatable)` | `commitEnrollment(Authenticatable $user, TwoFactorChannel $channel, string $reason): ?array` — запись `channel`, `confirmed_at = now()`, `enabled_at = now()` при добровольном подключении (остаётся при смене/перепривязке), `forget()` прежнего канала при смене, инкремент `trusted_devices_version` при смене/перепривязке, ротация `remember_token`, резервные коды (выпуск или удаление; возвращает открытые коды или null), `TwoFactorChannelChanged`, уведомление безопасности |
| `disable(Authenticatable)` | то же + `forget()` канала, удаление резервных кодов, `channel` → канал по умолчанию или null, `TwoFactorChannelChanged(reason: disabled)`, уведомление безопасности |
| `reset(Authenticatable)` | §5.10; `resetChannel(string $channel): int` — массовый сброс (§5.10) |
| `addressChanged(Authenticatable, string)` | обёртка над `destinationChanged(Authenticatable, string $channel, string $old)`; §5.11 |
| `forgetConfirmation`, `forgetTrustedDevices`, `rotateRememberToken`, `forgetAllRememberTokens` | без изменений |

`emailChannel()` берёт канал `email` из реестра (наследник `EmailChannel`, иначе базовый `EmailChannel`, как 0.1.1).

### 4.9. Хранение

- `two_factor_authentications` остаётся общей (§5.5 SPEC). Новая миграция `…_make_two_factor_channel_nullable`: `channel` nullable, без default (`null` — «не подключено»); существующие строки сохраняют `'email'`. Модель: `$attributes['channel']` убирается, при создании записи пишется канал по умолчанию, если он разрешён, иначе null. Колонок под конкретные драйверы нет и не будет.
- Новая миграция `…_create_two_factor_recovery_codes_table`: `id`, `user_id` (unsignedBigInteger, index, FK `users.id` cascadeOnDelete — те же оговорки, что §5.5 SPEC), `code_hash` string(255), `used_at` timestamp null, `created_at`.
- Данные драйверов — в их таблицах и миграциях (TOTP: `two_factor_totp`, §13). Стирание — только через `forget()`.
- Pending (`PendingLogin`) получает поля `channel`, `stage` (`challenge` | `enroll` | `recovery_codes`), `via` (`code` | `recovery_code` — чем пройден вызов перед enrollment, §5.4 Б) и `stage_started_at` (начало `stage = enroll`, §5.4 п. 7); pending 0.1.1 без них не принимается — пользователь входит заново (как в 0.1.1).
- `ProfileChallenge` получает действия `switch`, `rebind`, `regenerate`, `enroll` и поля `target` (имя канала), `step` (`confirm_current` | `enroll` | `show_codes`), `confirmed_at`. Пароль в `ProfileChallenge` не хранится: он проверяется в запросе подтверждения и сразу отбрасывается.
- Адаптер `Support\Orchid`: методы новых маршрутов (§6.4); `bin/check-adapter.php` разрешает `Orchid\` в `src/Testing/` (фикстуры наследуют классы Orchid), строки `platform.`/`platform::` там запрещены, как в UI-слое.

### 4.10. Публичный API

Под semver (в 0.x — ломающие изменения только в минорной версии с разделом Upgrade): `Contracts\*`, `Channels\DeliveryChannel`, `Channels\VerifierChannel`, `Channels\EmailChannel` (наследуемый), `Channels\ChannelRegistry` и `Facades\TwoFactor`, `Challenge\{Challenge, CodeInput, EnrollmentState, VerificationResult}`, `Events\*`, `Exceptions\*`, `Testing\*` (§10.2), имена конфигов, маршрутов, view, переводов. `@internal`: `CodeStore`, `StoredCode`, `PendingLogin`, `ProfileChallenge`, `Recovery\RecoveryCodes`, контроллеры. README — раздел «Writing a channel».

## 5. Сценарии

### 5.1. Вход, delivery-способ (email)

§4.1–§4.3, §4.10, §4.11 SPEC без изменений. Отличия: pending хранит `channel = email`; экран кода — общий шаблон с partial канала; события несут `channel`.

### 5.2. Вход, verifier-способ (TOTP)

1. Пароль, рехеш, `requires()`, доверенное устройство — §4.1, §4.2 п. 1–2 SPEC.
2. `ensureRecord()` и ротация `remember_token` при `confirmed_at = null` — как §4.5 SPEC.
3. `start(…, 'login')` → id, pending (`channel = totp`, `stage = challenge`), редирект на `platform.two-factor.challenge`; JSON — `200 {"two_factor": true, "redirect": …}`.
4. Экран кода: `prompt()` канала, поле по `codeInput()`, галочка доверия, «Использовать резервный код», при `allowsEmailFallback()` — «Прислать код на почту» (§13), «Войти под другим пользователем». Кнопки «Отправить повторно» нет.
5. Verify: проверки pending (§4.2 п. 5 SPEC: истёк, пароль изменён) → счётчики (§4.4) → `verifyCode()`.
   - неверный, попытки есть — `TwoFactorFailed(invalid_code)`, «неверный код, осталось N»;
   - 5-й неверный на pending — `TwoFactorLockedOut(attempts_exceeded)`, pending удаляется, редирект на логин «слишком много попыток, войдите снова»;
   - окно на пользователя исчерпано — `TwoFactorLockedOut(user_attempts_exceeded)`, «попробуйте через N мин», pending остаётся, уведомление безопасности `attempts_exceeded` (не чаще раза за окно);
   - суточный потолок исчерпан — `TwoFactorLockedOut(user_daily_attempts_exceeded)`, «попробуйте через N ч», pending остаётся (истечёт по `pending_ttl`), уведомление — как выше;
   - верный — `confirmed_at` (если null), cookie доверия, `TwoFactorPassed(via: code)`, финальный вход.
6. Повтор только что принятого кода в другой сессии — `Invalid` (защита драйвера, проверяется набором соответствия).

### 5.3. Вход по резервному коду

1. На экране кода verifier-способа с `needsRecoveryCodes()` — ссылка «Использовать резервный код» (форма с полем `recovery_code`, `POST platform.two-factor.recovery`, **без галочки доверия**). Ссылка видна, даже если неиспользованных кодов нет (не раскрываем остаток до верного кода); тогда любой ввод — `Invalid`.
2. Проверки pending как в verify; счётчики per-challenge, окно на пользователя и суточный потолок (§4.4).
3. Верный — код погашен, `confirmed_at`, `TwoFactorPassed(via: recovery_code)`, `RecoveryCodeUsed(remaining)`, уведомление безопасности, финальный вход; в сессии флаг `orchid-2fa.recovery_login`. Cookie доверия не выдаётся: маршрут игнорирует `trust_device`, даже если поле прислано (иначе потерявший телефон 30 дней не заметил бы, что перепривязка не сделана). Если вход продолжается enrollment (§5.4 Б), галочки нет и на его экранах.
4. Способ остаётся включённым. Профиль показывает баннер «вы вошли по резервному коду, осталось N; если устройство утеряно — перепривяжите способ».
5. Коды кончились и устройства нет — только сброс администратором (§5.10).

### 5.4. Enrollment при входе

Условие: 2FA требуется (принудительный; у добровольного способ всегда есть), действующего способа нет (§4.5 п. 4), то есть email не разрешён или не является каналом по умолчанию.

**Вариант А — подтверждённого способа нет** (новый пользователь, после сброса, `channel = null`): защита — только пароль (первая привязка, как у Fortify).
1. После пароля: `ensureRecord()` с ротацией `remember_token`, `session()->regenerate()`, pending `stage = enroll`, редирект на `platform.two-factor.enroll`. JSON — `200 {"two_factor": true, "enroll": true, "redirect": …}` (пароль верен, pending создан; дальше — только HTML, JSON-запрос к маршрутам enrollment получает `406`, §6.4).
2. Разрешённых каналов несколько — выбор; один — сразу шаг подключения.
3. `startEnrollment()`; экран: `enrollmentView()` драйвера + поле кода + «Войти под другим пользователем».
4. `confirmEnrollment()` под счётчиками §4.4 (verifier — включая окно, потолок и уведомление о подборе); 5 неверных — pending удаляется, снова пароль.
5. Успех — `commitEnrollment(reason: enrolled)`: `channel`, `confirmed_at`, резервные коды, `TwoFactorChannelChanged`, уведомление безопасности (если адрес есть).
6. Если выпущены резервные коды — `stage = recovery_codes`, экран `platform.two-factor.recovery-codes` с кодами и «Я сохранил коды» → финальный вход (`remember` из pending), `TwoFactorPassed(via: enrollment)`. Галочка доверия — на этом экране (кроме pending с `via = recovery_code`, §5.3).
7. Срок: при переходе pending в `stage = enroll` отсчёт начинается заново — `enrollment_ttl` (900 с) от `stage_started_at` вместо `pending_ttl`; покрывает выбор способа, установку приложения, скан QR и экран резервных кодов. Продления нет; отпечаток пароля проверяется на каждом шаге, как в verify.

**Вариант Б — подтверждённый способ есть, но не разрешён** (§4.5 п. 2; например, после `channels.allowed = ['totp']` у пользователей 0.1 с `channel = email` и `confirmed_at` не null): сначала обычный вызов этим способом (§5.1/§5.2) или резервным кодом (§5.3, если способ их имеет), после верного кода — pending переходит в `stage = enroll` (JSON — `200 {"two_factor": true, "enroll": true, "redirect": …}` вместо `204`) и шаги 2–7 варианта А; enrollment без доказательства прежним способом невозможен. Если `confirmed_at = null` при неразрешённом email — вариант А (адрес не подтверждён, доказательства нет). Альтернатива «считать неразрешённый способ отсутствующим» отвергнута: она дала бы злоумышленнику с паролем привязать свой способ, как только администратор сузит `allowed`.

### 5.5. Подключение в профиле (добровольное включение)

1. Статус `disabled`. «Включить» → выбор из `TwoFactor::allowed()` (один — без выбора).
2. Enrollment выбранного канала в профиле (§6.3): email — код на адрес (как §4.7 SPEC); TOTP — QR, ключ, код.
3. Успех — `commitEnrollment(reason: enrolled)`, `enabled_at = now()`, ротация `remember_token` (как §4.7 SPEC), коды показываются один раз, событие, уведомление.

### 5.6. Смена способа в профиле

1. «Сменить способ» → выбор из разрешённых, кроме текущего. Переход verifier → email — только если email разрешён (иначе его нет в списке).
2. Подтверждение текущим способом: текущий пароль и в той же форме код действующего способа (email — код на адрес, контекст `switch`; TOTP — код приложения) **или резервный код** (`RecoveryCodeUsed` с `context = profile`): принудительный пользователь, потерявший телефон, уходит на email по резервному коду без сброса. Подтверждение действует `profile.confirmation_ttl` (600 с) и привязано к пользователю, действию и целевому каналу.
3. Enrollment нового канала (§5.5 п. 2).
4. `commitEnrollment(reason: switched)`: `forget()` прежнего канала, инкремент `trusted_devices_version`, ротация `remember_token`, резервные коды выпускаются или удаляются, `enabled_at` не меняется.
5. Принудительный пользователь может менять способ (не может только выключить).
6. **Пароль** (здесь и в §5.7–§5.9): поле `password` в форме подтверждения, проверка `provider->validateCredentials($user, ['password' => …])` до проверки кода. Неверный пароль — ошибка на `password` (`errors.invalid_password`), код не проверяется и не гасится (резервный тоже), попытка засчитывается в те же счётчики, что неверный код этого действия (§4.4): перебор пароля из украденной сессии ограничен так же, как перебор кода. Пароль не сохраняется ни в сессии, ни в `ProfileChallenge`.

### 5.7. Перепривязка (смена телефона)

1. «Перепривязать» — для каналов с состоянием подключения (verifier; delivery — если `enrollmentView() !== null`). У email кнопки нет (смена адреса — в профиле Orchid, §5.11).
2. Подтверждение: текущий пароль и код текущего способа **или** резервный код (`RecoveryCodeUsed` с `context = profile`), §5.6 п. 6.
3. Enrollment того же канала: новый секрет; старый действует до успешного подтверждения нового.
4. `commitEnrollment(reason: rebound)`: данные драйвера заменены, инкремент версии, ротация `remember_token`, новый набор резервных кодов.

### 5.8. Выключение 2FA в профиле

Только добровольному (принудительному — `403`, как §4.7 SPEC). Подтверждение текущим паролем и кодом текущего способа или резервным кодом (§5.6 п. 6; для email-пользователя пароль — новое требование к потоку §4.7 SPEC) → `TwoFactorManager::disable()` (§4.8): `enabled_at = confirmed_at = null`, инкремент версии, `forget()` канала, удаление резервных кодов, `channel` → по умолчанию или null, `TwoFactorChannelChanged(reason: disabled)`, уведомление безопасности `channel_changed`.

### 5.9. Перевыпуск резервных кодов

Текущий пароль и код текущего способа (не резервный), §5.6 п. 6 → новый набор, показ один раз, `RecoveryCodesRegenerated`.

### 5.10. Сброс администратором и `orchid-2fa:reset`

Операция 0.1.1 (§4.8 SPEC: `enabled_at = confirmed_at = null`, инкремент `trusted_devices_version`, `clear()` кодов и счётчиков, ротация `remember_token`) плюс:
- `forget()` канала из `record.channel`, если драйвер зарегистрирован. Если нет (пакет удалён) — сбрасываются только данные основного пакета, лог `warning`; данные драйвера остаются в его таблицах (TOTP: `two_factor_totp`) и на вход не влияют: способ определяет `record.channel`, который больше не указывает на этот канал. При переустановке драйвера устаревшая строка перезаписывается следующим enrollment (§13); удалить раньше — откат миграции драйвера или вручную. Строки удаляются и каскадом при удалении пользователя;
- удаление резервных кодов, сброс окна, суточного потолка и маркера уведомления;
- `channel` → `'email'`, если email разрешён, иначе null (следующий вход принудительного — enrollment, §5.4 вариант А);
- `TwoFactorChannelChanged(reason: reset)` (в 0.1 сброс событий не порождал, §4.8 SPEC) и уведомление безопасности `channel_changed` на адрес пользователя.

Layout — без изменений интерфейса, тексты обобщаются («способ входа и резервные коды будут удалены»). Команда: `orchid-2fa:reset {email?} {--channel=} {--force}` — ровно одно из `email` и `--channel` (оба или ни одного — ошибка, код 1).

- `orchid-2fa:reset {email}` — как 0.1.1 (поиск по `channels.email.attribute`, подтверждение, `--force` его пропускает).
- `orchid-2fa:reset --channel=<name>` — массовый сброс всех пользователей с `two_factor_authentications.channel = <name>` (`TwoFactorManager::resetChannel()`), например после удаления драйвера (§4.5 п. 3). Имя **не** сверяется с реестром: команда работает и для незарегистрированного канала — тогда для каждого пользователя сбрасываются только данные основного пакета, как выше, и выводится предупреждение, что данные драйвера остались в его таблицах. Перед сбросом выводится число пользователей и запрашивается подтверждение; `--force` пропускает его, без `--force` в non-interactive — отказ, код 1. Обход — `chunkById`, каждый пользователь — отдельная операция §5.10 (транзакция, события, уведомление; при большом числе — `notification.queue`); пользователь, которого не вернул провайдер guard, пропускается с предупреждением. Итог — число сброшенных и пропущенных; 0 записей — сообщение, код 0.

### 5.11. Смена e-mail

- Канал пользователя `email`: §4.9 SPEC без изменений (уведомление на старый адрес, аннулирование кода, `confirmed_at = null`, cookie доверия перестают действовать).
- Канал verifier (TOTP): уведомление на старый адрес — как раньше; способ, его подтверждение и `confirmed_at` не затрагиваются; доверенные устройства не аннулируются (адрес не участвует во втором факторе). Активный e-mail-код (fallback, §13) аннулируется; сам fallback перестаёт быть доступен, пока адрес не совпадёт с привязанным при подключении TOTP (вернуть — перепривязка, §13).
- Реализация: `HasTwoFactor` вызывает `addressChanged()` → `destinationChanged($user, 'email', $old)`; `forgetConfirmation()` — только если `record.channel === 'email'` (или null). Исправление 0.1.1 (обнулял у записи любого канала) — этап 1 (§4.5, §12). Для будущих delivery-драйверов со своим адресатом (телефон) — тот же `destinationChanged()` с их именем канала, вызывает драйвер.

## 6. UI и точки расширения

### 6.1. Что даёт драйвер

| Точка | Метод | Где используется |
|---|---|---|
| Имя способа | `label()` | выбор способа, статус в профиле, `TwoFactorResetLayout`, `TwoFactorProfileLinkLayout` |
| Строка-подсказка | `prompt()` | экран кода, шаг кода профиля |
| Поле кода | `codeInput()` | общий partial поля |
| Фрагмент экрана кода | `challengeView()` | вместо общего partial (инструкция, особый ввод); получает `$channel`, `$user`, `$codeInput` |
| Шаг подключения | `enrollmentView()` + `enrollmentData()` | гостевой экран enrollment при входе и экран профиля (через `Layout::view()`), один partial на оба контекста; поле `code` и кнопки рисует основной пакет |

Partial — Blade без `@extends`, без форм и без внешних ресурсов (CSP); данные — только из `enrollmentData()`. В 0.2 драйверу достаточно partial: отдельного Orchid-Layout (`profileLayout()`) в контракте нет. Драйверу с интерактивом Orchid (WebAuthn — JS-вызов браузера) он понадобится; добавляется в 0.3 необязательным методом базового класса, без ломки контракта.

### 6.2. Экран кода `orchid-2fa::challenge`

Переменные 0.1 сохраняются (`destination`, `codeLength`, `codePattern`, `resendAvailableIn`, `verifyUrl`, `resendUrl`, `cancelUrl`, `trustDevice`, `trustDeviceDays`, `error`, `status`) — опубликованный шаблон 0.1 продолжает работать для email. Новые: `channel` (имя), `prompt`, `codeInput`, `challengeView`, `canResend` (= `requiresDelivery()`), `recoveryUrl` (null, если резервных кодов у способа нет), `fallbackUrl` (null без fallback). Форма резервного кода галочку доверия не рисует (§5.3). Общий partial поля: `orchid-2fa::partials.code-input`. Опубликованный шаблон 0.1 не покажет ссылку на резервный код — README советует перепубликовать.

Новые гостевые view: `orchid-2fa::enroll` (выбор способа и шаг подключения), `orchid-2fa::recovery-codes` (показ кодов при входе).

### 6.3. Экран профиля `TwoFactorProfileScreen`

Блоки: «Статус» (статус, способ `label()`, `prompt`/маска адреса для delivery, кнопки «Включить», «Сменить способ», «Перепривязать», «Выключить» по правам §5.5–§5.8); «Подтверждение» (поле текущего пароля `password` с `autocomplete="current-password"` для смены, перепривязки, выключения и перевыпуска, поле кода, «Использовать резервный код» для смены, перепривязки и выключения, «Отправить повторно» для delivery, «Отмена»); «Подключение» (`Layout::view(enrollmentView())` + поле кода); «Резервные коды» (остаток, предупреждение при ≤2, «Перевыпустить», одноразовый показ с «Я сохранил»); баннер после входа по резервному коду; «Доверенные устройства» (без изменений). Выбор способа показывает только `TwoFactor::allowed()`.

Методы экрана (`POST profile/two-factor/{method}`): 0.1 `sendEnableCode`, `enable`, `sendDisableCode`, `disable`, `cancelCode`, `forgetTrustedDevices` сохраняются (для email-потока поведение §4.7 SPEC, кроме пароля в `disable`, §5.8); новые: `chooseChannel`, `startSwitch`, `startRebind`, `startRegenerate`, `sendConfirmCode`, `confirmCurrent`, `confirmEnrollment`, `acknowledgeRecoveryCodes`. Статусы: `required`, `enabled`, `disabled`, `not_enrolled`.

`TwoFactorProfileLinkLayout`, `TwoFactorResetLayout`, экран профиля: способ (`label()`) и маска адреса — по способу пользователя (`TwoFactor::for()`), а не по глобальному `channel`, как в 0.1.1 (этап 1, §12); маска — только для delivery.

### 6.4. Маршруты (новые)

Группа, guest-middleware и throttle по IP — как §5.3 SPEC. Не регистрируются при `platform.auth = false` (как `two-factor*`).

| Метод | URI | Имя | Throttle |
|---|---|---|---|
| POST | `two-factor/recovery` | `platform.two-factor.recovery` | `routes.throttle` |
| POST | `two-factor/fallback` | `platform.two-factor.fallback` | `routes.throttle` |
| GET | `two-factor/enroll/{channel?}` | `platform.two-factor.enroll` | — |
| POST | `two-factor/enroll/{channel}` | `platform.two-factor.enroll.confirm` | `routes.throttle` |
| GET | `two-factor/recovery-codes` | `platform.two-factor.recovery-codes` | — |
| POST | `two-factor/recovery-codes` | `platform.two-factor.recovery-codes.confirm` | — |

Пользователь — только из pending (§9 SPEC «Подмена `user_id`»); `{channel}` проверяется по `TwoFactor::allowed()`. JSON: `recovery` и `fallback` отвечают как verify/resend (§4.2 п. 7 SPEC). Enrollment и показ резервных кодов — только HTML: на `wantsJson()` все четыре маршрута `enroll*` и `recovery-codes*` отвечают `406 {"message": <errors.browser_required>, "redirect": <url HTML-страницы>}`, pending не меняется (клиент открывает `redirect` в браузере). `406`, а не `422`/`403`: запрос корректен и разрешён, нет лишь JSON-представления.

### 6.5. Переводы

Новые строки en/ru в `orchid-2fa::messages`: выбор способа, enrollment, резервные коды, баннер, смена/перепривязка, `errors.too_many_attempts`, `errors.too_many_attempts_today`, `errors.channel_unavailable`, `errors.invalid_recovery_code`, `errors.invalid_password`, `errors.browser_required`, `challenge.app_prompt`, поле пароля в профиле, уведомление безопасности (все `$event`, §8.3). Тексты 0.1 о «коде на почту» (`profile.description`, `profile_link.description`, `reset.description`) обобщаются. Драйверы держат свои строки в своём namespace (`orchid-2fa-totp::messages`). `TranslationsTest` проверяет паритет ключей.

## 7. Конфиг: новые и изменённые ключи

Остальные — §7 SPEC без изменений.

| Ключ | По умолчанию | Назначение |
|---|---|---|
| `channel` | `'email'` | **смысл уточнён:** канал по умолчанию для пользователя без подключённого способа; действует, только если разрешён и delivery |
| `channels.allowed` | `['email', 'totp']` | разрешённые способы; имя без драйвера игнорируется (warning в `local`/`testing`, в проде молча, видно в `about`); ошибка — только если разрешённых не осталось (§4.3) |
| `channels.email.driver` | `EmailChannel::class` | **новый** (был `channels.email.class`; `class` читается как fallback до 0.3) |
| `channels.email.attribute` | `'email'` | без изменений |
| `channels.<name>.driver` | — | имя из `extend()` или class-string |
| `verify.user_max_attempts` | `10` | неверных кодов verifier-канала и резервных кодов на пользователя за окно |
| `verify.user_decay` | `600` | окно, с; также период, не чаще которого шлётся `attempts_exceeded` |
| `verify.user_max_per_day` | `30` | суточный потолок тех же попыток на пользователя (окно 24 ч, фиксировано) |
| `enrollment_ttl` | `900` | срок enrollment при входе (`stage = enroll` и показ резервных кодов) от начала шага, с; заменяет `pending_ttl` на этом шаге |
| `recovery_codes.count` | `8` | кодов в наборе |
| `recovery_codes.warn_at` | `2` | предупреждение в профиле при остатке ≤ N |
| `profile.confirmation_ttl` | `600` | срок подтверждения текущим способом и шага подключения в профиле, с |
| `notification.security.enabled` | `true` | все уведомления безопасности (§8.3), включая `attempts_exceeded` |
| `notification.security_class` | `TwoFactorSecurityNotification::class` | класс уведомления |

`code.max_attempts` (5) теперь также лимит неверных на один pending verifier-канала и на одно подтверждение в профиле (неверный пароль считается как неверный код, §5.6 п. 6). `pending_ttl` (600) не меняется и действует до перехода в `stage = enroll`. Ключей TOTP в основном конфиге нет (§13).

## 8. События и уведомления

### 8.1. Существующие события

Все получают `public readonly string $channel` (имя канала вызова; последний параметр конструктора). Новые значения констант:

| Событие | Добавлено |
|---|---|
| `TwoFactorChallengeSent` | (`channel` уже есть) `context`: `switch`, `rebind`, `regenerate`, `enroll`, `fallback`; только delivery-каналы |
| `TwoFactorPassed` | `via`: `recovery_code`, `enrollment` |
| `TwoFactorFailed` | `reason`: `invalid_recovery_code`, `channel_unavailable` |
| `TwoFactorLockedOut` | `reason`: `user_attempts_exceeded` (окно), `user_daily_attempts_exceeded` (суточный потолок); `availableIn` — до разблокировки соответствующего счётчика |

`TwoFactorPassed` по-прежнему только событие входа; профиль его не порождает. Суточный потолок — причина `TwoFactorLockedOut`, а не новое событие: слушатели блокировок (мониторинг) получают его без подписки на новый класс.

### 8.2. Новые события

| Событие | Свойства (кроме `user`, `guard`) |
|---|---|
| `TwoFactorChannelChanged` | `?string $from`, `?string $to`, `string $reason`: `enrolled`, `switched`, `rebound`, `disabled`, `reset` (в 0.1 выключение и сброс событий не имели, §5.7 SPEC; теперь — для аудита) |
| `RecoveryCodeUsed` | `string $channel`, `int $remaining`, `string $context`: `login`, `profile` |
| `RecoveryCodesRegenerated` | `string $channel`, `int $count` |

`LogTwoFactorEvents` подписывается и на них (без кодов, секретов и масок адресов сверх 0.1).

### 8.3. Уведомление безопасности

`Notifications\TwoFactorSecurityNotification(string $event, array $context)`; `$event`:

- `recovery_code_used` (context: `remaining`, `context`) — вход или подтверждение в профиле резервным кодом;
- `channel_changed` (context: `from`, `to`, `reason`) — при каждом `TwoFactorChannelChanged`, включая `disabled` и `reset` (в том числе каждому пользователю массового сброса);
- `attempts_exceeded` (context: `channel`, `limit`: `window` | `day`, `available_in`) — исчерпано окно или суточный потолок (§4.4): «кто-то ввёл ваш пароль и подбирает код; если это не вы — смените пароль». Не чаще раза за `verify.user_decay`.

Отправляется на адрес `channels.email.attribute`, если он есть и `notification.security.enabled`; через `EmailChannel::notify()` (очередь — по `notification.queue`). Ошибка отправки — лог `error`, действие не срывается (как §4.9 SPEC). Класс подменяется (`notification.security_class`), контракт конструктора — как выше. При смене способа уведомление уходит на текущий адрес.

## 9. Безопасность

Угрозы §9 SPEC действуют. Новые:

| Угроза | Защита |
|---|---|
| Подмена второго фактора украденной сессией (привязать свой TOTP, выключить 2FA) | Смена, перепривязка, выключение и перевыпуск требуют **текущего пароля** и кода текущего способа в одной форме (смена, перепривязка и выключение — или резервного кода); неверный пароль считается как неверный код; подтверждение привязано к сессии, пользователю, действию, целевому каналу и живёт 10 мин; принудительный не может выключить (сервер); уведомление безопасности при каждом изменении, включая выключение и сброс. Пароль закрывает и риск §9 SPEC «украденная сессия + смена адреса без пароля в `UserProfileScreen`»: код смены способа на новом адресе злоумышленника без пароля бесполезен. README по-прежнему рекомендует пароль при смене адреса в стабе (уведомление о смене уходит на старый адрес) |
| Enrollment при входе только по паролю | Только если подтверждённого способа нет (вариант А §5.4); при наличии — сначала его код или резервный код (вариант Б); session regenerate, pending с отпечатком пароля, `enrollment_ttl`; уведомление безопасности; событие. Принятый риск первой привязки (как Fortify) — README |
| Перебор TOTP | Инкремент до сравнения; 5 на pending (затем снова пароль), 10 за 10 мин и 30 за 24 ч на пользователя, throttle по IP. Оценка при допуске ±1 шаг (3·10⁻⁶ на попытку): за сутки ≈ 30 × 3·10⁻⁶ ≈ 0,009 %, за месяц непрерывного перебора ≈ 0,27 % (без потолка — ≈ 0,4 % в сутки и ≈ 12 % в месяц), нужен пароль. Владелец узнаёт о подборе из уведомления `attempts_exceeded` (§8.3); `TwoFactorLockedOut` — сигнал для мониторинга. Цена: злоумышленник с паролем может держать владельцу вход по коду закрытым до суток (как лимиты отправки §4.11 SPEC) — README |
| Повтор TOTP-кода | Драйвер принимает шаг строго больше последнего принятого (атомарный условный UPDATE); набор соответствия проверяет повтор в другой сессии и параллельный verify |
| Резервные коды | ~39,6 бит, только хеши (`Hash::make`, переживают ротацию `app.key`), атомарное погашение, общие лимиты с кодами verifier (окно и суточный потолок), показ один раз, уведомление при использовании, перевыпуск — только кодом способа и паролем; при входе по резервному коду галочка доверия не показывается и cookie не выдаётся |
| E-mail fallback TOTP и смена адреса | Fallback работает, только пока текущий адрес совпадает с HMAC адреса, сохранённым при подключении TOTP (§13): смена адреса из украденной сессии не открывает обход TOTP кодом на новый адрес |
| JSON-клиент на шаге enrollment | Маршруты enrollment и резервных кодов отвечают `406` на JSON (§6.4): коды и секреты не отдаются машиночитаемо |
| Утечка секретов драйвера | Основной пакет секретов не хранит; TOTP — `encrypted` cast; секрет enrollment — только в серверной сессии до подтверждения |
| Удалённый или сломанный драйвер | Fail-closed (§4.5 п. 3), без тихого понижения до email; исключения `verifyCode()` → `Invalid` + лог; `issue()` → `DeliveryFailedException` |
| Злонамеренный или кривой драйвер | Граница доверия — composer-зависимость: драйвер выполняется в процессе приложения и может всё. Основной пакет гарантирует независимо от драйвера: пользователь только из сессии, лимиты считаются до вызова драйвера, вызов другого канала не принимается, финальный вход, cookie доверия, ротация remember и события — только в ядре, тип канала — по базовому классу, `issue()`/`verify()` delivery-канала — `final`. Набор соответствия (§10.2) проверяет корректность честного драйвера (неверный/пустой/чужой/повторный код отклоняется, `forget()` стирает подключение, нет секретов в логах и событиях), но не защищает от злонамеренного |
| Понижение способа администратором | Удаление канала из `channels.allowed` не отключает 2FA: прежний способ остаётся доказательством для перехода (§5.4 вариант Б) |
| Удалённый драйвер и массовый сброс | `orchid-2fa:reset --channel` — только из консоли (права приложения не нужны, доступ к консоли и так полный), подтверждение с числом пользователей, каждому — событие и уведомление безопасности |
| Опечатка в `channels.allowed` | Имя без драйвера игнорируется (видно в `about` и логе `local`); пустой итоговый список — исключение в разработке и fail-closed в проде (§4.3) |
| Смена способа и старые cookie | Смена/перепривязка — инкремент `trusted_devices_version` и ротация `remember_token` |

## 10. Тестирование

### 10.1. Тесты основного пакета

- Все тесты 0.1.1 (`tests/Feature/*`) проходят без изменения сценариев; меняются только конструкции, завязанные на удалённый API (`tfFixCodes()` подменяет генерацию кода в `EmailChannel`/`DeliveryChannel`, а не в `ChallengeManager`). Единственное изменение сценария — с этапа 2 тесты выключения в профиле передают текущий пароль (§5.8); плюс тест «без пароля / с неверным паролем — не выключается».
- Способ пользователя вместо глобального (этап 1, §4.5): `channel` в конфиге ≠ `record.channel` — вход идёт каналом записи; `addressChanged()` не обнуляет `confirmed_at` у записи не-email канала; маска в `TwoFactorResetLayout` и профиле — канала пользователя. До этапа 2 — на тестовом delivery-канале (`tests/Fixtures/FakeDeliveryChannel`).
- Реестр: `driver` class-string и `extend()`, fallback `class`, неизвестное имя в `allowed` (warning в `testing`, молча в `production`, раздел в `about`), пустой итоговый `allowed` (исключение в `testing`, `critical` и fail-closed в `production`), не-наследник базового класса — исключение.
- Действующий способ (§4.5, все 4 ветки), включая удалённый драйвер (fail-closed) и неразрешённый подключённый способ.
- Enrollment при входе (А и Б, в Б — и по резервному коду), `enrollment_ttl` (шаг живёт дольше `pending_ttl`, истекает от `stage_started_at`), JSON: логин и verify с переходом в enroll — `200 {"enroll": true}`, маршруты enrollment и резервных кодов — `406`.
- Переходы профиля (§5.5–§5.9): пароль обязателен для смены, перепривязки, выключения и перевыпуска; неверный пароль не гасит код и считается попыткой; резервный код принимается для смены, перепривязки и выключения, не для перевыпуска.
- Сброс (§5.10): событие `reset` и уведомление; `orchid-2fa:reset --channel` — все пользователи канала и только они, подтверждение и `--force`, non-interactive без `--force` — код 1, `email` вместе с `--channel` — код 1, незарегистрированный канал (данные основного пакета сброшены, таблица драйвера не тронута, предупреждение).
- Смена e-mail для email- и verifier-пользователя (§5.11); резервные коды (формат, хеши `Hash::make`, атомарность, показ один раз, предупреждение, баннер, нет cookie доверия при входе по коду даже с `trust_device=1`).
- Лимиты verifier: окно на пользователя (смена pending не обнуляет), суточный потолок 30 (резервные коды в том же счётчике, `user_daily_attempts_exceeded`, `availableIn`), уведомление `attempts_exceeded` ровно одно за окно и не отправляется при `notification.security.enabled = false`.
- События (`disabled`, `reset`), уведомления безопасности при выключении и сбросе, миграции (up/down, nullable `channel`, существующие строки).
- Драйвер-заглушка `tests/Fixtures/FakeVerifierChannel` (`VerifierChannel`, имя `fake`, своя таблица в тестовой миграции, детерминированные коды по шагу времени, защита от повтора, `needsRecoveryCodes() = true`) — прогоняется через набор соответствия и используется в тестах сценариев verifier.

### 10.2. Набор соответствия `Nakipelo\Orchid2FA\Testing`

Поставляется в `src/Testing/` (тот же PSR-4, что `src/`): доступен драйверам из dist пакета; в проде не загружается, пока на него никто не ссылается. Зависит от `orchestra/testbench` и PHPUnit/Pest, которых нет в `require` (только `suggest` + README: «require-dev драйвера»). Larastan анализирует его в dev-окружении пакета; `bin/check-adapter.php` — исключение для `Orchid\` (§4.9).

Состав:
- `ChannelConformanceTestCase` — абстрактный PHPUnit-`TestCase` на Testbench (Pest запускает его без адаптера); поднимает Orchid, пакет, фикстурную модель `Testing\Fixtures\User` (с `HasTwoFactor`) и `users`;
- хуки драйвера (abstract): `channelName(): string`, `channelProviders(): array`, `enroll(User $user): void` (привести в подключённое состояние напрямую), `validCode(User $user): string`, `invalidCode(User $user): string`, `nextCodeWindow(): void` (для повтора; delivery — no-op), `completeEnrollmentCode(User $user, EnrollmentState $state): string`;
- группы тестов (трейты, можно отключить переопределением с `markTestSkipped` только для неприменимого, например `resend` у verifier): вход (верный, неверный, пустой, чужой пользователь, вызов другого канала), лимиты (per-challenge, окно на пользователя, суточный потолок verifier, delivery — cooldown/час), обходы (verify без pending, `user_id` в теле, повтор кода в другой сессии, параллельный verify), доверенные устройства (выдача, пропуск, инкремент при смене способа), remember (выдача только после 2FA, ротация при enrollment и сбросе), сброс (`isAvailableFor` = false после `forget()`, идемпотентность `forget()`, повторный enrollment поверх оставшихся данных драйвера), резервные коды (если `needsRecoveryCodes()`; вход без cookie доверия), enrollment (без верного кода данных нет, отмена стирает state), отсутствие кодов и секретов в логах и событиях.

Почтовый драйвер (`EmailChannel`) и драйвер-заглушка проходят набор в CI основного пакета; TOTP — в CI своего репозитория.

## 11. Upgrade 0.1 → 0.2 (README и CHANGELOG)

Для приложений только с e-mail:
1. `composer require nakipelo/orchid-2fa:^0.2`, `php artisan migrate` (nullable `channel`, `two_factor_recovery_codes`). Опубликованные миграции 0.1 не трогать; новые грузятся из пакета.
2. Опубликованный конфиг работает без правок (`channels.email.class` читается как `driver`); рекомендуется переименовать в `driver` и добавить `channels.allowed`. Без ключа `allowed` действует умолчание `['email', 'totp']`.
3. Опубликованный `challenge.blade.php` работает для email; перепубликовать, чтобы получить ссылку на резервный код и partial канала.
4. Активные pending 0.1.1 не принимаются: пользователи на шаге кода в момент деплоя входят заново.
5. Поведение входа, лимиты, cookie доверия и remember для email не меняются.
6. Изменения для пользователей: выключение 2FA в профиле требует текущий пароль (§5.8); выключение и сброс администратором порождают `TwoFactorChannelChanged` и письмо-уведомление (отключается `notification.security.enabled`).
7. Новые ключи конфига с умолчаниями (§7) действуют без публикации: `verify.user_max_attempts`, `verify.user_decay`, `verify.user_max_per_day`, `enrollment_ttl`, `recovery_codes.*`, `profile.confirmation_ttl`, `notification.security*`.

**Массовый перевод с e-mail на TOTP** — одной строкой конфига: установить `nakipelo/orchid-2fa-totp`, `migrate`, затем `'channels' => ['allowed' => ['totp'], …]`. Каждый пользователь с подтверждённым e-mail (`confirmed_at` не null) при следующем входе вводит код с почты как доказательство и сразу подключает TOTP (§5.4 Б); вход без подключения невозможен. Пользователи с `confirmed_at = null` (адрес сменён или вход без 2FA до включения требования) подключают TOTP только по паролю (§5.4 А) — README советует перед переключением проверить их число. Добровольные пользователи переводятся так же; выключивших 2FA переключение не затрагивает. Откат — вернуть `email` в `allowed` (уже подключённый TOTP остаётся действующим способом).

**Удаление драйвера** (например, TOTP): до удаления пакета — `php artisan orchid-2fa:reset --channel=totp --force` (или после: команда работает и без драйвера, §5.10). Иначе пользователи канала не войдут (fail-closed, §4.5 п. 3). Таблица `two_factor_totp` после удаления пакета остаётся — удалить вручную или откатить миграцию до удаления.

Ломающие изменения API (для своих каналов и интеграций):
- `Contracts\TwoFactorChannel` — новый контракт (§4.1); канал 0.1 с `send()/destination()/maskedDestination()` переносится наследованием от `DeliveryChannel` (методы те же) и регистрацией в `channels.<name>.driver`.
- `ChallengeManager::channel()` удалён (`TwoFactor::for($user)` / `TwoFactor::channel($name)`); `issue()`/`verify()` принимают и возвращают `Challenge` вместо строки id.
- `TwoFactorManager::enable()` → `commitEnrollment()`.
- События получают обязательный параметр конструктора `channel` (слушатели не затрагиваются); `TwoFactorLockedOut::$reason` — новые значения `user_attempts_exceeded`, `user_daily_attempts_exceeded`.
- Модель: `channel` nullable.
- `orchid-2fa:reset`: аргумент `email` стал необязательным (взаимоисключим с `--channel`); вызов `orchid-2fa:reset <email>` работает как раньше.

Раздел README «Writing a channel»: выбор базового класса, обязательные методы, регистрация `extend()`, свой конфиг и миграции, `forget()`, partial'ы, переводы, подключение набора соответствия, semver-обязательства и зависимость `^0.2`.

## 12. Этапы

Каждый этап: `composer check` зелёный по матрице §2 SPEC; поведение email-входа не меняется (тесты 0.1.1 зелёные). Реализация — субагентами, проверка и коммиты — вручную.

**1. Контракт и email на новом API.** `Contracts\TwoFactorChannel`, `Challenge`, `CodeInput`, `EnrollmentState` (каркас), `DeliveryChannel`, `VerifierChannel` (каркас), `ChannelRegistry` + `TwoFactor`, `EmailChannel` на `DeliveryChannel`, `ChallengeManager` как оркестратор (счётчики до драйвера), `channel` в событиях, `PendingLogin.channel`, fallback `channels.*.class`. Перевод расхождений 0.1.1 на способ пользователя (§4.5): канал при входе — из `record.channel` (зарегистрирован — он, иначе `channel` по умолчанию; полная логика §4.5 — этап 2), `addressChanged()` обнуляет `confirmed_at` только у записи `email`/null, `TwoFactorResetLayout` и экран профиля берут маску из канала пользователя.
*Готово, когда:* все существующие тесты проходят (правка только тестовых хелперов, завязанных на удалённый API); тесты реестра и «способ пользователя вместо глобального» §10.1 (вход каналом записи при другом `channel` в конфиге, `confirmed_at` не-email записи переживает смену адреса, маска в Layout сброса и профиле — канала пользователя); `grep` по `src/` не находит чтения `config('orchid-2fa.channel')` вне реестра; Larastan level 8 без baseline; `bin/check-adapter.php` чистый.

**2. Функциональность 0.2.** Миграции, точки расширения UI (§6), резервные коды, `channels.allowed` и его проверка, действующий способ (§4.5), enrollment при входе (`enrollment_ttl`, `406` для JSON), переходы профиля с паролем и резервным кодом, сброс и `orchid-2fa:reset --channel`, смена e-mail для verifier, окно на пользователя и суточный потолок, уведомление о подборе, новые события, уведомления безопасности (включая выключение и сброс), переводы, `Testing\*`, `FakeVerifierChannel`.
*Готово, когда:* сценарии §5.2–§5.11 и пункты §10.1 покрыты тестами на заглушке; email и заглушка проходят набор соответствия; ручная проверка в workbench с заглушкой (вход, enrollment при входе с `allowed = ['fake']` и массовый перевод email → fake по §11, смена email↔fake по коду и по резервному коду, перепривязка, выключение с паролем, резервный код без cookie доверия, сброс, `reset --channel=fake` после удаления `extend('fake')`, письмо о подборе); набор соответствия подключается из другого пакета через `composer` path-repository (проверено на черновике TOTP).

**3. Пакет TOTP** в новом репозитории (§13).
*Готово, когда:* требования §13 выполнены; набор соответствия зелёный по матрице; ручная проверка с Google Authenticator в workbench (QR, вход, повтор, ±1 шаг, fallback до и после смены адреса).

**4. Документация обоих.** README (установка, «Writing a channel», Upgrade 0.1→0.2 с массовым переводом на TOTP и удалением драйвера, ограничения: первая привязка по паролю, коды кончились — сброс, удаление драйвера — fail-closed и `reset --channel`, `enrollment_ttl`, блокировка входа по коду до суток при подборе, пароль для изменений 2FA в профиле), CHANGELOG, обновление `docs/SPEC.md`: ссылка на этот файл, «кандидат на v0.2» для middleware в §1, §5.4, §9 SPEC → v0.3; README и CHANGELOG TOTP (fallback и смена адреса).
*Готово, когда:* чистая установка обоих пакетов в свежий Laravel + Orchid по README проходит; обновление проекта с 0.1.1 на 0.2 по разделу Upgrade проходит без правок кода приложения (только `migrate`).

**5. Ревью и релизы.** Независимое ревью Fable обоих пакетов (контракт, безопасность, набор соответствия), исправления, релиз `nakipelo/orchid-2fa` 0.2.0 (тег, Packagist), затем `nakipelo/orchid-2fa-totp` 0.1.0 с зависимостью `^0.2`.
*Готово, когда:* замечания ревью закрыты или вынесены в открытые вопросы следующей версии; CI обоих зелёный на тегах; первый потребитель обновлён на `^0.2` и подключил TOTP.

## 13. Требования к пакету `nakipelo/orchid-2fa-totp` 0.1.0

Контракт для будущего SPEC пакета; полная спецификация — отдельно.

- **Пакет:** `nakipelo/orchid-2fa-totp`, github.com/nakipelo/orchid-2fa-totp, MIT, своя нумерация, неймспейс `Nakipelo\Orchid2FATotp`, провайдер с auto-discovery; `require`: `nakipelo/orchid-2fa ^0.2`, `pragmarx/google2fa`, `bacon/bacon-qr-code`; PHP/Laravel/Orchid — как у основного.
- **Регистрация:** `TwoFactor::extend('totp', …)` в `boot()`; канал `totp` — наследник `VerifierChannel`; активен, если `totp` в `orchid-2fa.channels.allowed` (по умолчанию да).
- **Алгоритм:** RFC 6238, SHA1, 6 цифр, шаг 30 с; настраивается только допуск `totp.window` (по умолчанию 1 шаг в обе стороны). Защита от повтора: принимается только шаг > `last_step`, атомарный условный UPDATE.
- **Хранение:** миграция `two_factor_totp`: `user_id` (unique, FK `users.id` cascadeOnDelete, оговорки §5.5 SPEC), `secret` (text, `encrypted` cast на `app.key`), `confirmed_at`, `last_step` (unsigned bigint null), `email_hash` (string(64) null — HMAC адреса на момент подключения), timestamps. `isAvailableFor` = запись с `confirmed_at`. `forget()` удаляет запись. Строка может пережить сброс без драйвера (§5.10) — на вход не влияет.
- **Enrollment:** секрет (160 бит) в `EnrollmentState` → `enrollmentView()` показывает QR (SVG `bacon/bacon-qr-code`, генерация на сервере, без внешних сервисов) и ключ текстом группами → первый верный код → запись с `confirmed_at`, `last_step` и `email_hash` — upsert по `user_id`: устаревшая строка (после сброса без драйвера) заменяется целиком. Перепривязка заменяет секрет и `email_hash` только после подтверждения нового.
- **otpauth-URI:** `issuer` = `config('app.name')`, `label` = e-mail пользователя (атрибут `channels.email.attribute`); оба переопределяемы конфигом/замыканием.
- **E-mail fallback:** `totp.email_fallback` (по умолчанию `false`). `allowsEmailFallback()` = true, только если одновременно: `email_fallback = true`; `email` зарегистрирован и в `channels.allowed`; `email_hash` не null и совпадает с `hash_hmac('sha256', mb_strtolower(trim(<текущий адрес>)), app.key)` (сверка также с `APP_PREVIOUS_KEYS`; адрес — `channels.email.attribute`). Тогда на экране кода «Прислать код на почту» (механизм ядра: `POST two-factor/fallback`, контекст `fallback`, лимиты delivery). `email_hash` пишется только при подключении и перепривязке, не при входе: после смены адреса (в том числе из украденной сессии, §9 SPEC) fallback недоступен, пока владелец не перепривяжет TOTP. Ядро повторно проверяет `allowsEmailFallback()` в `POST two-factor/fallback`.
- **Конфиг** `config/orchid-2fa-totp.php`: `window`, `email_fallback`, `issuer`, `label`.
- **UI:** partial'ы `orchid-2fa-totp::enroll`, при необходимости `challengeView()`; переводы en/ru в `orchid-2fa-totp::messages`.
- **Тесты:** `ChannelConformanceTestCase` основного пакета зелёный; свои — алгоритм (RFC-векторы), допуск, повтор, QR/URI, шифрование секрета, `app.key` с `APP_PREVIOUS_KEYS`, fallback (выключен по умолчанию, недоступен без `email` в `allowed`, недоступен после смены адреса, возвращается перепривязкой, `email_hash` при ротации ключа), enrollment поверх устаревшей строки.
- **README/Limitations:** ротация `app.key` без `APP_PREVIOUS_KEYS` делает секреты нечитаемыми (вход только через резервные коды или сброс) и отключает fallback до перепривязки; время сервера должно быть синхронизировано (NTP); первая привязка защищена только паролем; потеря телефона и кодов — сброс администратором; смена адреса отключает fallback до перепривязки; удаление пакета — сначала `orchid-2fa:reset --channel=totp` (§11).

## 14. Открытые вопросы

Открытых вопросов нет: решения внесены в §1–§13.
