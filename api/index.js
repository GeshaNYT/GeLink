// ============================================================
//  GeLink API — index.js
//  Улучшения: Redis-хелпер (нет injection), JWT выдаётся при логине
//  Фронт не требует JWT — обратная совместимость сохранена
// ============================================================

import { SignJWT, jwtVerify } from 'jose';

const JWT_ALG = 'HS256';
// Токен живёт долго: настоящий срок жизни входа определяет запись сеанса в базе (sess:<id>).
// Завершили сеанс в «Устройствах» — токен сразу перестаёт работать, даже если он ещё не истёк.
const JWT_TTL = '180d';

// ── Стабильный ID пользователя (НЕ email) ─────────────────────
// Раньше id личной комнаты строился из email обеих сторон (private-<хеш1>-<хеш2>).
// Из-за этого при удалении аккаунта и повторной регистрации ТОЙ ЖЕ почтой
// получалась ТА ЖЕ самая комната — старая история переписки и статусы (включая
// "аккаунт удалён" в кэше у собеседников) как будто "воскресали", хотя по факту
// это уже другой человек/аккаунт. Теперь у каждого аккаунта есть свой userId,
// который выдаётся один раз при регистрации и никогда не меняется, а id личной
// комнаты строится из userId, а не из email — так что новый аккаунт с той же
// почтой гарантированно получает НОВУЮ, чистую комнату.
function generateUserId() {
    if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    // Резервный вариант, если randomUUID недоступен в конкретном рантайме
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Генерирует userId и явно проверяет в базе, что он ещё никем не занят (через
// обратный индекс id_email) — на случай столкновения. Столкновение для случайного
// 128-битного UUID практически невозможно (вероятность пренебрежимо мала), но раз
// проверка дешёвая — лучше перестраховаться и не полагаться только на теорию
// вероятностей. При совпадении просто пробуем снова (ограничение попыток — просто
// защита от бесконечного цикла на случай сбоя самой проверки, а не ожидаемый сценарий).
async function generateUniqueUserId(db) {
    for (let attempt = 0; attempt < 5; attempt++) {
        const candidate = generateUserId();
        const taken = await db('EXISTS', `id_email:${candidate}`);
        if (!taken) return candidate;
    }
    // Сюда мы практически никогда не попадём — но на всякий случай не блокируем
    // регистрацию/операцию полностью, а возвращаем последнюю сгенерированную попытку.
    return generateUserId();
}

// Возвращает userId аккаунта, генерируя и сохраняя его при первом обращении —
// это покрывает и новые регистрации, и аккаунты, созданные ДО введения этого поля.
async function getUserId(db, email) {
    let userId = await db('HGET', `profile:${email}`, 'userId');
    if (!userId) {
        userId = await generateUniqueUserId(db);
        await db('HSET', `profile:${email}`, 'userId', userId);
        await db('SET', `id_email:${userId}`, email); // обратный индекс userId -> email
    }
    return userId;
}

// Определяет id личной комнаты для пары emailA/emailB, ПРЕДПОЧИТАЯ уже существующую
// комнату новой. До перехода на userId комнаты строились из email — некоторые пары
// пользователей уже могут иметь такую "старую" комнату с историей переписки. Если
// создавать для них комнату заново по новой схеме (userId), получится дубликат:
// два разных чата с одним и тем же человеком (старый с историей + новый пустой) —
// например, ровно это происходит при "удалил контакт -> добавил обратно", если
// комната была создана ДО перехода на userId. Поэтому здесь сначала проверяем,
// нет ли уже существующей комнаты (по старой ИЛИ по новой схеме — есть ли в ней
// сообщения или числится ли она в списке комнат хотя бы одного из участников), и
// только если совсем ничего нет — создаём новую по актуальной (userId) схеме.
async function resolvePrivateRoomId(db, emailA, emailB) {
    const oldSafeA = emailA.replace(/[@.]/g, '').toLowerCase();
    const oldSafeB = emailB.replace(/[@.]/g, '').toLowerCase();
    const oldRoomId = `private-${[oldSafeA, oldSafeB].sort().join('-')}`;

    const userIdA = await getUserId(db, emailA);
    const userIdB = await getUserId(db, emailB);
    const newRoomId = `private-${[userIdA, userIdB].sort().join('-')}`;

    // Старую комнату проверяем ПЕРВОЙ (приоритет — сохранить более длинную историю).
    for (const candidate of [oldRoomId, newRoomId]) {
        const [hasMessages, inRoomsA, inRoomsB] = await Promise.all([
            db('EXISTS', `room:${candidate}`),
            db('SISMEMBER', `user_rooms:${emailA}`, candidate),
            db('SISMEMBER', `user_rooms:${emailB}`, candidate),
        ]);
        if (hasMessages === 1 || inRoomsA === 1 || inRoomsB === 1) return candidate;
    }
    // Ни старой, ни новой комнаты ещё нет — совсем новая пара, создаём по актуальной схеме
    return newRoomId;
}

// ── SHA-256 хеш пароля ───────────────────────────────────────
// sha256Hex — низкоуровневый хелпер БЕЗ соли. Это ровно тот формат, что
// использовался раньше (до этого обновления) — оставляем его как есть, чтобы
// не ломать уже сохранённые в базе хеши старых аккаунтов.
async function sha256Hex(str) {
    const data = new TextEncoder().encode(str);
    const buf  = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// hashPassword — НОВЫЙ формат (с солью), используется для всех регистраций и
// смен пароля начиная с этого обновления. Соль хранится рядом в поле "salt"
// каждого профиля и делает хеш уникальным для каждого пользователя — без неё
// одинаковые пароли у разных людей давали бы совершенно одинаковый хеш, и
// заранее просчитанные "радужные таблицы" могли бы вскрыть пароль мгновенно.
async function hashPassword(password, salt) {
    return sha256Hex(`${salt}:${password}`);
}

// Случайная соль на аккаунт (16 байт = 32 hex-символа)
function generateSalt() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Шифрование сообщений "в покое" (at rest) ─────────────────────────────
// Раньше сообщения (текст, фото/файлы в base64, голосовые и т.д.) писались в
// Redis обычным JSON-текстом — то есть при прямом доступе к базе (утечка
// креденшлов Upstash, дамп базы и т.п.) их мог прочитать кто угодно, хотя в
// политике конфиденциальности заявлено "храним сообщения в зашифрованном
// виде". Теперь тело каждого сообщения шифруется AES-256-GCM ключом,
// производным от секрета сервера, перед записью в Redis, и расшифровывается
// сразу после чтения — сам формат данных, который видит фронт, не меняется.
//
// Это шифрование "в покое" (защищает от чтения базы напрямую), а не полное
// end-to-end шифрование (когда даже сервер не может прочитать сообщение) —
// для настоящего E2E нужны были бы ключи на стороне каждого клиента и обмен
// ими, что требует отдельной, более крупной переработки.
let _cachedMsgKey = null;
async function getMessageKey(env) {
    if (_cachedMsgKey) return _cachedMsgKey;
    // Если отдельный MESSAGE_ENCRYPTION_KEY не задан — используем JWT-секрет
    // (плюс фиксированную соль-разделитель), чтобы шифрование работало из
    // коробки. Рекомендуется всё же задать отдельный секрет в переменных
    // окружения — тогда компрометация одного секрета не затронет второй.
    const secret = env.msgSecret || `${env.jwt}::gelink-message-key`;
    const keyMaterial = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret));
    _cachedMsgKey = await crypto.subtle.importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    return _cachedMsgKey;
}

function bytesToBase64(bytes) {
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
}
function base64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
}

// Шифрует произвольную строку (обычно JSON.stringify(msg)) для хранения в Redis.
// Формат: "enc:<iv в base64>:<шифротекст в base64>"
async function encryptForStorage(plainText, env) {
    const key = await getMessageKey(env);
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-бит nonce, стандарт для AES-GCM
    const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plainText));
    return `enc:${bytesToBase64(iv)}:${bytesToBase64(new Uint8Array(cipherBuf))}`;
}

// Расшифровывает запись из Redis обратно в ту же обёртку (encodeURIComponent от
// JSON), что фронт всегда ожидал получить — благодаря этому клиентский код
// вообще не нужно менять. Записи в СТАРОМ (нешифрованном) формате, оставшиеся
// с более ранних версий, просто возвращаются как есть — обратная совместимость.
async function decryptStoredMessage(raw, env) {
    if (typeof raw !== 'string' || !raw.startsWith('enc:')) return raw;
    try {
        const [, ivB64, cipherB64] = raw.split(':');
        const key = await getMessageKey(env);
        const iv = base64ToBytes(ivB64);
        const cipherBytes = base64ToBytes(cipherB64);
        const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipherBytes);
        return encodeURIComponent(new TextDecoder().decode(plainBuf));
    } catch (e) {
        // Не роняем всю загрузку истории из-за одной повреждённой записи
        return raw;
    }
}

// ── Единый Redis-клиент (тело запроса, не URL) ───────────────
async function redis(env, ...args) {
    const res = await fetch(env.url, {
        method: 'POST',
        headers: {
            Authorization:  `Bearer ${env.token}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(args),
    });
    if (!res.ok) throw new Error(`Redis error ${res.status}: ${await res.text()}`);
    return (await res.json()).result;
}

// ── JWT ──────────────────────────────────────────────────────
function jwtSecret(s) { return new TextEncoder().encode(s); }

async function signToken(payload, secret) {
    return new SignJWT(payload)
        .setProtectedHeader({ alg: JWT_ALG })
        .setExpirationTime(JWT_TTL)
        .setIssuedAt()
        .sign(jwtSecret(secret));
}

// Ошибка «войдите заново»: сеанс завершён, токен поддельный или устарел.
function authError(message = 'Сеанс завершён. Войдите в GeLink снова.') {
    return Object.assign(new Error(message), { status: 401, code: 'auth' });
}

// ── Хелпер: hgetall → объект ─────────────────────────────────
function parseHash(raw) {
    const out = {};
    if (!Array.isArray(raw)) return out;
    for (let i = 0; i < raw.length; i += 2) out[raw[i]] = raw[i + 1];
    return out;
}

// ── Генерация ID группы: 8 символов, A-Z0-9 ──────────────────
const GROUP_ID_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
// Зарезервированный ID общего канала General — никогда не выдаётся новым группам
const GENERAL_GROUP_ID = '00000000';
function genGroupId() {
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    let id = '';
    for (let i = 0; i < 8; i++) id += GROUP_ID_CHARS[bytes[i] % GROUP_ID_CHARS.length];
    return id;
}

// Генерирует ID и проверяет через EXISTS, что такой группы ещё нет
// (а также что это не зарезервированный ID General)
async function generateUniqueGroupId(db) {
    for (let attempt = 0; attempt < 25; attempt++) {
        const id = genGroupId();
        if (id === GENERAL_GROUP_ID) continue;
        const exists = await db('EXISTS', `group:${id}`);
        if (!exists) return id;
    }
    throw new Error('Не удалось сгенерировать уникальный ID группы');
}

// Публикует системное сообщение в чат группы (о вступлении/выходе участника)
async function pushSystemMessage(db, roomId, text, email, env) {
    const msg = {
        type: 'system',
        text,
        ts: Date.now(),
        username: 'System',
        email: email || '',
    };
    await db('LPUSH', `room:${roomId}`, await encryptForStorage(JSON.stringify(msg), env));
}
// ── OAuth 2.0: «Войти через GeLink» для сторонних сайтов ─────
// Зарегистрированные клиенты берутся из переменной окружения OAUTH_CLIENTS (JSON):
// {"minva": {"name": "Minva Messenger", "secret": "...", "redirect_uris": ["https://.../callback"]}}
const OAUTH_CODE_TTL  = 60;    // секунд живёт одноразовый code
const OAUTH_TOKEN_TTL = 3600;  // секунд живёт access_token
const OAUTH_SCOPES    = ['profile', 'email'];

function getOAuthClient(clientId) {
    if (!clientId) return null;
    let clients;
    try { clients = JSON.parse(process.env.OAUTH_CLIENTS || '{}'); } catch { return null; }
    const c = clients[clientId];
    if (!c || !c.secret || !Array.isArray(c.redirect_uris)) return null;
    return c;
}

function randomHex(n = 32) {
    return Array.from(crypto.getRandomValues(new Uint8Array(n)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// Сравнение строк за постоянное время (чтобы секрет нельзя было подобрать по таймингу)
function safeEqual(a, b) {
    a = String(a ?? ''); b = String(b ?? '');
    let diff = a.length ^ b.length;
    for (let i = 0; i < Math.max(a.length, b.length); i++)
        diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    return diff === 0;
}

async function pkceS256(verifier) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    return bytesToBase64(new Uint8Array(buf)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function normalizeScope(scope) {
    const list = String(scope || 'profile').split(/[\s+]+/).filter(s => OAUTH_SCOPES.includes(s));
    if (!list.includes('profile')) list.unshift('profile');
    return [...new Set(list)].join(' ');
}

function readBody(request) {
    const b = request.body;
    if (!b) return {};
    if (typeof b === 'string') {
        try { return JSON.parse(b); } catch { return Object.fromEntries(new URLSearchParams(b)); }
    }
    return b;
}

function getHeader(request, name) {
    return request.headers.get?.(name) ?? request.headers[name] ?? '';
}

// ── «Войти через Minva»: GeLink как OAuth-клиент Minva ─────────
// Переменные окружения: MINVA_URL, MINVA_CLIENT_ID (по умолчанию gelink), MINVA_CLIENT_SECRET,
// PUBLIC_URL (адрес GeLink, необязательно — иначе берётся из заголовков запроса).
// Адрес возврата, который нужно зарегистрировать в Minva: <PUBLIC_URL>/api/index?action=minvaCallback
function minvaConfig() {
    const url = (process.env.MINVA_URL || '').replace(/\/+$/, '');
    const id = process.env.MINVA_CLIENT_ID || 'gelink';
    const secret = process.env.MINVA_CLIENT_SECRET || '';
    return { url, id, secret, enabled: Boolean(url && secret) };
}

function publicBase(request) {
    if (process.env.PUBLIC_URL) return process.env.PUBLIC_URL.replace(/\/+$/, '');
    const host = getHeader(request, 'x-forwarded-host') || getHeader(request, 'host');
    const proto = (getHeader(request, 'x-forwarded-proto') || 'https').split(',')[0].trim();
    return `${proto}://${host}`;
}

function readCookie(request, name) {
    for (const part of String(getHeader(request, 'cookie') || '').split(/;\s*/)) {
        const i = part.indexOf('=');
        if (i > 0 && part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1));
    }
    return null;
}

// Cookie привязывает вход к этому браузеру: чужая ссылка с code/state у жертвы не сработает.
function minvaCookie(request, value, maxAge) {
    const secure = publicBase(request).startsWith('https://') ? '; Secure' : '';
    return `ge_minva=${encodeURIComponent(value)}; Path=/api; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

function redirectTo(response, url, cookie) {
    if (cookie) response.setHeader('Set-Cookie', cookie);
    response.setHeader('Location', url);
    response.setHeader('Cache-Control', 'no-store');
    return response.status(302).end();
}

function cleanNick(raw) {
    let n = String(raw || '').toLowerCase().replace(/[^a-z0-9_]/g, '');
    if (!n || !/^[a-z]/.test(n)) n = 'm' + n;
    return n.slice(0, 20);
}

async function freeNick(db, raw) {
    const base = cleanNick(raw);
    const tries = [base, ...Array.from({ length: 6 }, () => base + (1000 + Math.floor(Math.random() * 9000))), 'm' + randomHex(5)];
    for (const n of tries) if (!(await db('GET', `nick:${n}`))) return n;
    return 'm' + randomHex(8);
}

async function minvaProfile(cfg, code, verifier, redirectUri) {
    const res = await fetch(`${cfg.url}/api/v1/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grant_type: 'authorization_code', code, redirect_uri: redirectUri,
            client_id: cfg.id, client_secret: cfg.secret, code_verifier: verifier }),
    });
    const tok = await res.json().catch(() => ({}));
    if (!res.ok || !tok.access_token) throw new Error('token: ' + (tok.error || res.status));
    const res2 = await fetch(`${cfg.url}/api/v1/oauth/userinfo`, { headers: { Authorization: `Bearer ${tok.access_token}` } });
    const info = await res2.json().catch(() => ({}));
    if (!res2.ok || typeof info.sub !== 'string' || !info.sub) throw new Error('userinfo: ' + res2.status);
    return info;
}

// ══════════════════════════════════════════════════════════════
//  СЕАНСЫ (устройства), КОДЫ ВХОДА, ОФИЦИАЛЬНЫЙ БОТ GeLink
// ══════════════════════════════════════════════════════════════
const SESSION_TTL_SEC    = 180 * 24 * 3600;     // сеанс без активности живёт 180 дней
const NEW_SESSION_LOCK   = 24 * 3600 * 1000;    // новое устройство 24 ч не может завершать другие сеансы
const CODE_TTL_SEC       = 15 * 60;             // код действует 15 минут (так написано и в письме)
const CODE_MAX_ATTEMPTS  = 5;
const CODE_RESEND_MS     = 60 * 1000;
const BOT_EMAIL          = 'official@gelink';
const BOT_ROOM_PREFIX    = 'official-';

const botRoomFor = userId => `${BOT_ROOM_PREFIX}${userId}`;

// «Chrome · Windows», «GeLink для ПК · Windows», «Приложение GeLink · Android»…
function describeDevice(ua) {
    ua = String(ua || '');
    let os = 'Неизвестное устройство';
    if (/Windows NT/i.test(ua)) os = 'Windows';
    else if (/iPhone/i.test(ua)) os = 'iPhone';
    else if (/iPad/i.test(ua)) os = 'iPad';
    else if (/Android/i.test(ua)) os = 'Android';
    else if (/Mac OS X|Macintosh/i.test(ua)) os = 'macOS';
    else if (/CrOS/i.test(ua)) os = 'ChromeOS';
    else if (/Linux/i.test(ua)) os = 'Linux';
    let app;
    if (/Electron\//i.test(ua)) app = 'GeLink для ПК';
    else if (/; wv\)|GeLinkApp/i.test(ua)) app = 'Приложение GeLink';
    else if (/YaBrowser/i.test(ua)) app = 'Яндекс Браузер';
    else if (/Edg\//i.test(ua)) app = 'Edge';
    else if (/OPR\/|Opera/i.test(ua)) app = 'Opera';
    else if (/Firefox\//i.test(ua)) app = 'Firefox';
    else if (/Chrome\//i.test(ua)) app = 'Chrome';
    else if (/Safari\//i.test(ua)) app = 'Safari';
    else app = 'Браузер';
    return `${app} · ${os}`;
}

// Город и страна по IP — Vercel сам добавляет эти заголовки к каждому запросу
function requestPlace(request) {
    const dec = v => { try { return decodeURIComponent(v || ''); } catch { return v || ''; } };
    const city = dec(getHeader(request, 'x-vercel-ip-city'));
    const country = dec(getHeader(request, 'x-vercel-ip-country'));
    let countryName = country;
    try { if (country) countryName = new Intl.DisplayNames(['ru'], { type: 'region' }).of(country) || country; } catch {}
    return [city, countryName].filter(Boolean).join(', ');
}

function requestIp(request) {
    return String(getHeader(request, 'x-forwarded-for') || getHeader(request, 'x-real-ip') || '').split(',')[0].trim();
}

async function createSession(db, email, request, via = 'password') {
    const sid = randomHex(16);
    const now = String(Date.now());
    await db('HSET', `sess:${sid}`,
        'email', email, 'created', now, 'lastSeen', now, 'via', via,
        'device', describeDevice(getHeader(request, 'user-agent')),
        'place', requestPlace(request), 'ip', requestIp(request));
    await db('EXPIRE', `sess:${sid}`, SESSION_TTL_SEC);
    await db('SADD', `user_sessions:${email}`, sid);
    return sid;
}

// Живые сеансы пользователя (заодно вычищает из списка истёкшие)
async function liveSessions(db, email) {
    const sids = (await db('SMEMBERS', `user_sessions:${email}`)) ?? [];
    const out = [];
    for (const sid of sids) {
        const s = parseHash(await db('HGETALL', `sess:${sid}`));
        if (s.email === email) out.push({ sid, ...s });
        else await db('SREM', `user_sessions:${email}`, sid);
    }
    return out;
}

async function endSession(db, email, sid) {
    await db('DEL', `sess:${sid}`);
    await db('SREM', `user_sessions:${email}`, sid);
}

// Сообщение от официального бота GeLink в служебный чат пользователя.
// Бот пишет открытым текстом (без E2E: это сообщения сервера, а не другого человека),
// в базе они хранятся зашифрованными, как и все остальные сообщения.
async function botSend(db, env, email, text, extra = {}) {
    const userId = await getUserId(db, email);
    if (!userId) return;
    const room = botRoomFor(userId);
    const msg = { username: 'GeLink', email: BOT_EMAIL, bot: true, text, ts: Date.now(), status: 'sent', ...extra };
    await db('SADD', `user_rooms:${email}`, room);
    await db('LPUSH', `room:${room}`, await encryptForStorage(JSON.stringify(msg), env));
    await db('LTRIM', `room:${room}`, 0, 199);
}

function fmtWhen(ms) {
    try {
        return new Date(Number(ms)).toLocaleString('ru-RU', { day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) + ' (UTC)';
    } catch { return ''; }
}

// Письмо с кодом — с сервера, через REST API EmailJS (тот же шаблон, что и раньше).
// Нужны: EMAILJS_PRIVATE_KEY (секрет из EmailJS → Account → API keys) и включённая
// в EmailJS → Account → Security опция «Allow EmailJS API for non-browser applications».
async function sendCodeEmail(email, name, code) {
    const privateKey = process.env.EMAILJS_PRIVATE_KEY;
    if (!privateKey) throw Object.assign(new Error('Отправка писем не настроена (EMAILJS_PRIVATE_KEY)'), { status: 503 });
    const res = await fetch(process.env.EMAILJS_API_URL || 'https://api.emailjs.com/api/v1.0/email/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            service_id:  process.env.EMAILJS_SERVICE_ID  || 'service_m7095tg',
            template_id: process.env.EMAILJS_TEMPLATE_ID || 'template_rfib6ri',
            user_id:     process.env.EMAILJS_PUBLIC_KEY  || 'cnvoZ3PqIBehf1lbC',
            accessToken: privateKey,
            template_params: { email, to_name: name || email, passcode: code, time: '15 минут' },
        }),
    });
    if (!res.ok) {
        console.error('[GeLink email]', res.status, (await res.text().catch(() => '')).slice(0, 200));
        throw Object.assign(new Error('Не удалось отправить письмо. Попробуйте позже.'), { status: 502 });
    }
}

function newCode() {
    const n = crypto.getRandomValues(new Uint32Array(1))[0] % 900000;
    return String(100000 + n);
}

// Одноразовая «заявка» с кодом: login | register | reset | password.
// Сам код в базе не хранится — только его хеш.
async function createChallenge(db, purpose, email, data = {}) {
    const id = randomHex(16);
    const code = newCode();
    await db('SET', `challenge:${id}`, JSON.stringify({
        purpose, email, data, codeHash: await sha256Hex(`${id}:${code}`), attempts: 0, sentAt: Date.now(),
    }), 'EX', CODE_TTL_SEC);
    return { id, code };
}

async function loadChallenge(db, id, purpose) {
    if (!id || typeof id !== 'string' || id.length > 64) return null;
    const raw = await db('GET', `challenge:${id}`);
    if (!raw) return null;
    const ch = JSON.parse(raw);
    return ch.purpose === purpose ? ch : null;
}

// Проверяет код. Возвращает challenge при успехе (и удаляет его), иначе бросает понятную ошибку.
async function checkChallenge(db, id, purpose, code) {
    const ch = await loadChallenge(db, id, purpose);
    if (!ch) throw Object.assign(new Error('Код устарел. Запросите новый.'), { status: 400, code: 'expired' });
    if (ch.attempts >= CODE_MAX_ATTEMPTS) {
        await db('DEL', `challenge:${id}`);
        throw Object.assign(new Error('Слишком много неверных попыток. Запросите новый код.'), { status: 429, code: 'expired' });
    }
    const ok = safeEqual(ch.codeHash, await sha256Hex(`${id}:${String(code || '').trim()}`));
    if (!ok) {
        ch.attempts += 1;
        const ttl = await db('TTL', `challenge:${id}`);
        await db('SET', `challenge:${id}`, JSON.stringify(ch), 'EX', Math.max(1, Number(ttl) || 1));
        throw Object.assign(new Error('Неверный код. Попробуйте ещё раз.'), { status: 400, code: 'wrong_code' });
    }
    await db('DEL', `challenge:${id}`);
    return ch;
}

// Заменяет код в существующей заявке (для «Отправить ещё раз / на почту»)
async function reissueChallenge(db, id, ch) {
    if (Date.now() - (ch.sentAt || 0) < CODE_RESEND_MS)
        throw Object.assign(new Error('Новый код можно запросить через минуту.'), { status: 429 });
    const code = newCode();
    ch.codeHash = await sha256Hex(`${id}:${code}`);
    ch.attempts = 0;
    ch.sentAt = Date.now();
    await db('SET', `challenge:${id}`, JSON.stringify(ch), 'EX', CODE_TTL_SEC);
    return code;
}

function maskEmail(email) {
    const [u, d] = String(email).split('@');
    if (!d) return email;
    return `${u.slice(0, 2)}${'•'.repeat(Math.max(1, Math.min(6, u.length - 2)))}@${d}`;
}

// ── Чёрный список ──────────────────────────────────────────────
// blocked:<email> — кого этот пользователь заблокировал
async function isBlockedBy(db, owner, other) {
    if (!owner || !other) return false;
    return (await db('SISMEMBER', `blocked:${owner}`, other)) === 1;
}

// Собеседник в личной комнате private-<userIdA>-<userIdB> (id отсортированы и склеены через «-»)
async function privatePeerEmail(db, room, myEmail) {
    if (!room.startsWith('private-')) return null;
    const myUid = await getUserId(db, myEmail);
    const rest = room.slice('private-'.length);
    if (!myUid || !rest.includes(myUid)) return null;
    const otherUid = rest.replace(myUid, '').replace(/^-|-$/g, '');
    return otherUid ? await db('GET', `id_email:${otherUid}`) : null;
}

// Профиль для чужих глаз: без пароля и служебных полей; кого владелец заблокировал —
// тот не видит его аватарку, «о себе» и что он в сети
async function publicProfile(db, email, viewer) {
    const profile = parseHash(await db('HGETALL', `profile:${email}`));
    for (const k of ['password', 'salt', 'e2eBackup', 'minvaSub', 'minvaOnly']) delete profile[k];
    if (!profile.userId) profile.userId = await getUserId(db, email);
    profile.online = (await db('EXISTS', `last_seen:${email}`)) === 1;
    if (viewer && viewer !== email && await isBlockedBy(db, email, viewer)) {
        delete profile.avImg;
        delete profile.bio;
        profile.online = false;
    }
    return profile;
}

// Всё, что фронт сохраняет после входа (как в старом ответе action=login)
function publicUser(email, userId, profile) {
    return {
        email, userId,
        name:     profile.name     ?? email,
        nickname: profile.nickname ?? '',
        avColor:  profile.avColor  ?? 'var(--ge-accent-gradient)',
        avImg:    profile.avImg    ?? null,
        bio:      profile.bio      ?? '',
        pubKey:   profile.pubKey   ?? null,
    };
}

// Сверка пароля (со всеми старыми форматами хранения и их миграцией)
async function checkPassword(db, emailLower, profile, password) {
    const storedPass = profile.password;
    const storedSalt = profile.salt || '';
    if (!storedPass || !password) return false;
    const isLegacyBase64 = storedPass.length !== 64 || !/^[0-9a-f]+$/.test(storedPass);
    if (isLegacyBase64) {
        let legacy;
        try { legacy = Buffer.from(password).toString('base64'); }
        catch { legacy = btoa(unescape(encodeURIComponent(password))); }
        const decoded = storedPass.startsWith('%') ? decodeURIComponent(storedPass) : storedPass;
        if (decoded !== legacy) return false;
    } else if (storedSalt) {
        return storedPass === await hashPassword(password, storedSalt);
    } else if (storedPass !== await sha256Hex(password)) {
        return false;
    }
    // старый формат совпал — сразу переводим на SHA-256 с солью
    const newSalt = generateSalt();
    await db('HSET', `profile:${emailLower}`, 'password', await hashPassword(password, newSalt), 'salt', newSalt);
    return true;
}

export default async function handler(request, response) {
    const env = {
        url:       process.env.UPSTASH_URL,
        token:     process.env.UPSTASH_TOKEN,
        jwt:       process.env.JWT_SECRET,
        msgSecret: process.env.MESSAGE_ENCRYPTION_KEY, // отдельный секрет для шифрования сообщений (опционально, см. getMessageKey)
    };

    if (!env.url || !env.token || !env.jwt) {
        return response.status(500).json({ status: 'error', message: 'Server misconfigured' });
    }

    const db = (...args) => redis(env, ...args);
    const { room = 'general', action, target_email } = request.query ?? {};

    // ── Кто делает запрос: только по токену сеанса ──────────────
    // Раньше почти все действия верили параметру user_email («я — такой-то»), и любой,
    // кто знал чужую почту, мог читать и менять чужой аккаунт. Теперь пользователь
    // определяется ТОЛЬКО по токену, а токен действует, пока жив его сеанс (sess:<id>).
    let authCache;
    const authenticate = async () => {
        if (authCache !== undefined) return authCache;
        authCache = null;
        const header = String(getHeader(request, 'authorization') || '');
        if (!header.startsWith('Bearer ')) return null;
        let payload;
        try { ({ payload } = await jwtVerify(header.slice(7), jwtSecret(env.jwt))); }
        catch { throw authError(); }
        if (!payload.sid || !payload.email) throw authError();
        const sess = parseHash(await db('HGETALL', `sess:${payload.sid}`));
        if (sess.email !== payload.email) throw authError('Этот сеанс завершён. Войдите в GeLink снова.');
        // «Был в сети» и место обновляем не чаще раза в минуту
        if (Date.now() - Number(sess.lastSeen || 0) > 60000) {
            const place = requestPlace(request);
            await db('HSET', `sess:${payload.sid}`, 'lastSeen', String(Date.now()), ...(place ? ['place', place] : []), 'ip', requestIp(request));
            await db('EXPIRE', `sess:${payload.sid}`, SESSION_TTL_SEC);
        }
        authCache = { email: payload.email, sid: payload.sid, session: sess };
        return authCache;
    };
    // Старые обработчики вызывают tryAuth(request, secret) — теперь он проверяет и сеанс
    const tryAuth = async () => (await authenticate())?.email ?? null;

    // Действия, которым вход не нужен. Всё остальное без действующего сеанса получает 401.
    const PUBLIC_ACTIONS = new Set([
        'oauthClientInfo', 'oauthToken', 'oauthUserinfo',
        'minvaConfig', 'minvaStart', 'minvaCallback', 'minvaFinish',
        'checkAvailable', 'register', 'registerStart', 'registerVerify', 'registerResend',
        'login', 'loginVerify', 'loginResend',
        'resetStart', 'resetVerify', 'resetFinish',
        'findUser',
    ]);

    try {
        if (!PUBLIC_ACTIONS.has(action) && !(await authenticate()))
            throw authError('Войдите в GeLink.');

        // ══════════════════════════════════════════════════════
        //  OAuth 2.0 — «Войти через GeLink»
        // ══════════════════════════════════════════════════════

        // Информация о клиенте для страницы подтверждения (публично, без секрета)
        if (action === 'oauthClientInfo') {
            const { client_id, redirect_uri } = request.query;
            const client = getOAuthClient(client_id);
            if (!client)
                return response.status(400).json({ status: 'error', message: 'Неизвестное приложение' });
            if (!client.redirect_uris.includes(redirect_uri))
                return response.status(400).json({ status: 'error', message: 'Недопустимый адрес возврата (redirect_uri)' });
            return response.status(200).json({ status: 'ok', name: client.name || client_id });
        }

        // Пользователь нажал «Разрешить» — выдаём одноразовый code.
        // Требует настоящий JWT: без него нельзя подтвердить вход от чужого имени.
        if (action === 'oauthApprove' && request.method === 'POST') {
            const email = await tryAuth(request, env.jwt);
            if (!email)
                return response.status(401).json({ status: 'error', message: 'Нужно войти в GeLink заново' });

            const { client_id, redirect_uri, state, scope, code_challenge, code_challenge_method } = readBody(request);
            const client = getOAuthClient(client_id);
            if (!client || !client.redirect_uris.includes(redirect_uri))
                return response.status(400).json({ status: 'error', message: 'Неизвестное приложение или redirect_uri' });
            if (code_challenge && (code_challenge_method || 'plain') !== 'S256')
                return response.status(400).json({ status: 'error', message: 'Поддерживается только PKCE S256' });
            if (await db('EXISTS', `profile:${email}`) !== 1)
                return response.status(401).json({ status: 'error', message: 'Аккаунт не найден' });

            const code = randomHex(32);
            await db('SET', `oauth_code:${code}`, JSON.stringify({
                client_id, redirect_uri, email,
                scope: normalizeScope(scope),
                code_challenge: code_challenge || null,
            }), 'EX', OAUTH_CODE_TTL);

            const url = new URL(redirect_uri);
            url.searchParams.set('code', code);
            if (state) url.searchParams.set('state', state);
            return response.status(200).json({ status: 'ok', redirect: url.toString() });
        }

        // Обмен code на access_token — вызывается СЕРВЕРОМ клиента (Minva), не браузером
        if (action === 'oauthToken' && request.method === 'POST') {
            const body = readBody(request);
            let { client_id, client_secret } = body;
            const basic = getHeader(request, 'authorization');
            if (basic.startsWith('Basic ')) {
                const [id, secret] = Buffer.from(basic.slice(6), 'base64').toString().split(':');
                client_id = decodeURIComponent(id || ''); client_secret = decodeURIComponent(secret || '');
            }
            const oauthErr = (status, error, desc) =>
                response.status(status).json({ error, error_description: desc });

            if (body.grant_type !== 'authorization_code')
                return oauthErr(400, 'unsupported_grant_type', 'Only authorization_code is supported');
            const client = getOAuthClient(client_id);
            if (!client || !safeEqual(client.secret, client_secret))
                return oauthErr(401, 'invalid_client', 'Bad client credentials');
            if (!body.code)
                return oauthErr(400, 'invalid_request', 'Missing code');

            // GETDEL — код можно использовать ровно один раз
            const raw = await db('GETDEL', `oauth_code:${body.code}`);
            if (!raw) return oauthErr(400, 'invalid_grant', 'Code is invalid or expired');
            const data = JSON.parse(raw);
            if (data.client_id !== client_id || data.redirect_uri !== body.redirect_uri)
                return oauthErr(400, 'invalid_grant', 'client_id or redirect_uri mismatch');
            if (data.code_challenge) {
                if (!body.code_verifier || await pkceS256(body.code_verifier) !== data.code_challenge)
                    return oauthErr(400, 'invalid_grant', 'PKCE verification failed');
            }

            const accessToken = randomHex(32);
            await db('SET', `oauth_at:${accessToken}`, JSON.stringify({
                email: data.email, client_id, scope: data.scope,
            }), 'EX', OAUTH_TOKEN_TTL);

            return response.status(200).json({
                access_token: accessToken,
                token_type:   'Bearer',
                expires_in:   OAUTH_TOKEN_TTL,
                scope:        data.scope,
            });
        }

        // Данные пользователя по access_token
        if (action === 'oauthUserinfo') {
            const auth = getHeader(request, 'authorization');
            if (!auth.startsWith('Bearer '))
                return response.status(401).json({ error: 'invalid_token' });
            const raw = await db('GET', `oauth_at:${auth.slice(7)}`);
            if (!raw) return response.status(401).json({ error: 'invalid_token' });
            const { email, scope } = JSON.parse(raw);

            const profile = parseHash(await db('HGETALL', `profile:${email}`));
            if (!profile.name && !profile.nickname)
                return response.status(401).json({ error: 'invalid_token', error_description: 'Account deleted' });

            const info = {
                sub:                profile.userId || await getUserId(db, email),
                name:               profile.name ?? '',
                preferred_username: profile.nickname ?? '',
                picture:            profile.avImg || null,
                bio:                profile.bio ?? '',
            };
            if (scope.split(' ').includes('email')) info.email = email;
            return response.status(200).json(info);
        }

        // ══════════════════════════════════════════════════════
        //  «Войти через Minva»
        // ══════════════════════════════════════════════════════
        if (action === 'minvaConfig') {
            return response.status(200).json({ enabled: minvaConfig().enabled });
        }

        // Шаг 1: фронт просит адрес страницы согласия Minva. mode=link — привязка к текущему аккаунту (нужен JWT).
        if (action === 'minvaStart' && request.method === 'POST') {
            const cfg = minvaConfig();
            if (!cfg.enabled) return response.status(404).json({ status: 'error', message: 'Вход через Minva не настроен' });
            const { mode } = readBody(request);
            let email = null;
            if (mode === 'link') {
                email = await tryAuth(request, env.jwt);
                if (!email) return response.status(401).json({ status: 'error', message: 'Войдите в GeLink заново' });
            }
            const state = randomHex(24);
            const browser = randomHex(16);
            const verifier = bytesToBase64(crypto.getRandomValues(new Uint8Array(48))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            await db('SET', `minva_state:${state}`, JSON.stringify({ verifier, mode: mode === 'link' ? 'link' : 'login', email, browser }), 'EX', 600);
            const url = new URL(cfg.url + '/oauth/authorize');
            url.search = new URLSearchParams({
                response_type: 'code', client_id: cfg.id, redirect_uri: publicBase(request) + '/api/index?action=minvaCallback',
                scope: 'profile email', state, code_challenge: await pkceS256(verifier), code_challenge_method: 'S256',
            }).toString();
            response.setHeader('Set-Cookie', minvaCookie(request, browser, 600));
            return response.status(200).json({ status: 'ok', url: url.toString() });
        }

        // Шаг 2: Minva вернула браузер с code и state
        if (action === 'minvaCallback') {
            const cfg = minvaConfig();
            const fail = (code) => redirectTo(response, `/?minva_error=${code}`, minvaCookie(request, '', 0));
            if (!cfg.enabled) return fail('not_configured');
            const { state, code, error } = request.query;
            const raw = state ? await db('GETDEL', `minva_state:${state}`) : null;
            const flow = raw ? JSON.parse(raw) : null;
            if (!flow || !safeEqual(flow.browser, readCookie(request, 'ge_minva'))) return fail('state');
            if (error) return fail(error === 'access_denied' ? 'denied' : 'exchange');
            if (!code) return fail('exchange');

            let info;
            try {
                info = await minvaProfile(cfg, code, flow.verifier, publicBase(request) + '/api/index?action=minvaCallback');
            } catch (e) {
                console.error('[GeLink minva]', e.message);
                return fail('exchange');
            }
            const sub = info.sub;
            const linkedEmail = await db('GET', `minva_sub:${sub}`);

            if (flow.mode === 'link') {
                if (await db('EXISTS', `profile:${flow.email}`) !== 1) return fail('state');
                if (linkedEmail && linkedEmail !== flow.email) return fail('taken');
                const current = await db('HGET', `profile:${flow.email}`, 'minvaSub');
                if (current && current !== sub) return fail('already_linked');
                await db('SET', `minva_sub:${sub}`, flow.email);
                await db('HSET', `profile:${flow.email}`, 'minvaSub', sub);
                return redirectTo(response, '/?minva=linked', minvaCookie(request, '', 0));
            }

            let email = null, isNew = false;
            if (linkedEmail && await db('EXISTS', `profile:${linkedEmail}`) === 1) {
                email = linkedEmail;
            } else {
                if (linkedEmail) await db('DEL', `minva_sub:${sub}`); // аккаунт GeLink был удалён
                // Почту Minva проверяет на сервере, поэтому ей можно доверять. Но если такой аккаунт GeLink
                // уже есть, не склеиваем автоматически: пусть войдёт паролем и привяжет Minva в настройках.
                const minvaEmail = info.email && info.email_verified ? String(info.email).trim().toLowerCase() : null;
                if (minvaEmail && await db('SISMEMBER', 'all_users', minvaEmail) === 1) return fail('email_exists');
                email = minvaEmail || `minva-${sub.replace(/[^a-z0-9]/gi, '').slice(0, 16).toLowerCase()}@users.minva`;
                if (await db('SISMEMBER', 'all_users', email) === 1) return fail('email_exists');
                const nick = await freeNick(db, info.preferred_username);
                const salt = generateSalt();
                const userId = await generateUniqueUserId(db);
                const fields = [
                    'name', String(info.name || nick).slice(0, 64), 'nickname', nick,
                    'avColor', 'var(--ge-accent-gradient)',
                    'password', await hashPassword(randomHex(32), salt), 'salt', salt, // пароль никто не знает
                    'userId', userId, 'minvaSub', sub, 'minvaOnly', '1',
                ];
                if (info.bio) fields.push('bio', String(info.bio).slice(0, 150));
                if (typeof info.picture === 'string' && info.picture.startsWith('data:image/') && info.picture.length < 3_000_000) fields.push('avImg', info.picture);
                await db('SADD', 'all_users', email);
                await db('HSET', `profile:${email}`, ...fields);
                await db('SET', `id_email:${userId}`, email);
                await db('SET', `nick:${nick}`, email);
                await db('SET', `minva_sub:${sub}`, email);
                await db('SREM', 'deleted_users', email);
                isNew = true;
            }
            const ticket = randomHex(24);
            await db('SET', `minva_ticket:${ticket}`, JSON.stringify({ email, isNew, browser: flow.browser }), 'EX', 120);
            return redirectTo(response, `/?minva_ticket=${ticket}`);
        }

        // Шаг 3: страница GeLink меняет одноразовый билет на обычную сессию (как после входа)
        if (action === 'minvaFinish' && request.method === 'POST') {
            const { ticket } = readBody(request);
            const raw = ticket ? await db('GETDEL', `minva_ticket:${ticket}`) : null;
            const data = raw ? JSON.parse(raw) : null;
            response.setHeader('Set-Cookie', minvaCookie(request, '', 0));
            if (!data || !safeEqual(data.browser, readCookie(request, 'ge_minva')))
                return response.status(400).json({ status: 'error', message: 'Вход через Minva устарел. Попробуйте ещё раз.' });
            const profile = parseHash(await db('HGETALL', `profile:${data.email}`));
            if (!profile.nickname && !profile.name)
                return response.status(400).json({ status: 'error', message: 'Аккаунт не найден' });
            const userId = profile.userId || await getUserId(db, data.email);
            const sid = await createSession(db, data.email, request, 'minva');
            const sess = parseHash(await db('HGETALL', `sess:${sid}`));
            await botSend(db, env, data.email, `✅ Новый вход в аккаунт через Minva: ${sess.device}${sess.place ? ', ' + sess.place : ''}, ${fmtWhen(sess.created)}.\nЕсли это были не вы — завершите этот сеанс в ⚙ → Конфиденциальность → Устройства.`);
            return response.status(200).json({
                status: 'ok',
                token: await signToken({ email: data.email, sid }, env.jwt),
                isNew: data.isNew,
                hasE2E: Boolean(profile.pubKey),
                passwordSet: profile.minvaOnly !== '1',
                user: {
                    email: data.email, userId,
                    name: profile.name ?? data.email, nickname: profile.nickname ?? '',
                    avColor: profile.avColor ?? 'var(--ge-accent-gradient)', avImg: profile.avImg ?? null, bio: profile.bio ?? '',
                },
            });
        }

        if (action === 'minvaStatus') {
            const email = await tryAuth(request, env.jwt);
            if (!email) return response.status(401).json({ status: 'error', message: 'Войдите в GeLink заново' });
            const [sub, only] = await Promise.all([db('HGET', `profile:${email}`, 'minvaSub'), db('HGET', `profile:${email}`, 'minvaOnly')]);
            return response.status(200).json({ status: 'ok', enabled: minvaConfig().enabled, linked: Boolean(sub), passwordSet: only !== '1' });
        }

        if (action === 'minvaUnlink' && request.method === 'POST') {
            const email = await tryAuth(request, env.jwt);
            if (!email) return response.status(401).json({ status: 'error', message: 'Войдите в GeLink заново' });
            const [sub, only] = await Promise.all([db('HGET', `profile:${email}`, 'minvaSub'), db('HGET', `profile:${email}`, 'minvaOnly')]);
            if (only === '1')
                return response.status(400).json({ status: 'error', message: 'Сначала задайте пароль в профиле — сейчас Minva единственный способ войти в аккаунт.' });
            if (sub) await db('DEL', `minva_sub:${sub}`);
            await db('HDEL', `profile:${email}`, 'minvaSub');
            return response.status(200).json({ status: 'ok' });
        }

        // ══════════════════════════════════════════════════════
        //  ПРОВЕРКА ДОСТУПНОСТИ email/никнейма — публичный, НИЧЕГО НЕ ПИШЕТ.
        //  Вызывается ДО отправки OTP-письма, чтобы дать быструю обратную связь,
        //  не резервируя при этом email/ник за незавершённой регистрацией.
        // ══════════════════════════════════════════════════════
        if (action === 'checkAvailable' && request.method === 'POST') {
            const { email, nickname } = request.body;
            if (!email || !nickname)
                return response.status(400).json({ status: 'error', message: 'Заполните все поля' });

            const emailLower = email.trim().toLowerCase();
            const nickLower  = nickname.trim().toLowerCase();

            if (await db('SISMEMBER', 'all_users', emailLower) === 1)
                return response.status(400).json({ status: 'error', message: 'Этот email уже зарегистрирован' });

            if (await db('GET', `nick:${nickLower}`))
                return response.status(400).json({ status: 'error', message: 'Этот никнейм уже занят' });

            return response.status(200).json({ status: 'ok' });
        }

        // ══════════════════════════════════════════════════════
        //  РЕГИСТРАЦИЯ  — публичный эндпоинт.
        //  ВАЖНО: реально пишет в базу (резервирует email и ник) и должна
        //  вызываться фронтом ТОЛЬКО ПОСЛЕ успешной проверки OTP-кода.
        //  Если писать сюда до отправки/подтверждения письма, то при сбое
        //  отправки (EmailJS упал/нет сети) email и ник останутся навечно
        //  "заняты" незавершённой регистрацией, и повторная попытка будет
        //  падать с "email уже зарегистрирован" / "никнейм уже занят".
        // ══════════════════════════════════════════════════════
        // Старый путь регистрации без проверки почты — закрыт: аккаунт создаётся
        // только после кода из письма (registerStart → registerVerify).
        if (action === 'register') {
            return response.status(410).json({ status: 'error', message: 'Обновите страницу GeLink (Ctrl+F5) и зарегистрируйтесь снова.' });
        }

        // ── РЕГИСТРАЦИЯ, шаг 1: проверяем данные и шлём код на почту ──
        if (action === 'registerStart' && request.method === 'POST') {
            const { email, password, name, nickname, avColor } = readBody(request);
            if (!email || !password || !name || !nickname)
                return response.status(400).json({ status: 'error', message: 'Заполните все поля' });
            const emailLower = String(email).trim().toLowerCase();
            const nickLower  = String(nickname).trim().toLowerCase();
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLower))
                return response.status(400).json({ status: 'error', message: 'Проверьте адрес почты' });
            if (!/^[a-z0-9_]{3,20}$/.test(nickLower))
                return response.status(400).json({ status: 'error', message: 'Никнейм: 3–20 символов, латиница, цифры, подчёркивание' });
            if (String(password).length < 8)
                return response.status(400).json({ status: 'error', message: 'Пароль слишком короткий!' });
            if (await db('SISMEMBER', 'all_users', emailLower) === 1)
                return response.status(400).json({ status: 'error', message: 'Этот email уже зарегистрирован' });
            if (await db('GET', `nick:${nickLower}`))
                return response.status(400).json({ status: 'error', message: 'Этот никнейм уже занят' });

            // Пароль в заявке храним уже захешированным — открытым он нигде не лежит
            const salt = generateSalt();
            const { id, code } = await createChallenge(db, 'register', emailLower, {
                name: String(name).slice(0, 64), nickname: nickLower, avColor: avColor || 'var(--ge-accent-gradient)',
                passHash: await hashPassword(String(password), salt), salt,
            });
            await sendCodeEmail(emailLower, name, code);
            return response.status(200).json({ status: 'ok', challenge: id, sentTo: 'email', email: maskEmail(emailLower) });
        }

        if (action === 'registerResend' && request.method === 'POST') {
            const { challenge } = readBody(request);
            const ch = await loadChallenge(db, challenge, 'register');
            if (!ch) return response.status(400).json({ status: 'error', message: 'Регистрация устарела. Начните заново.' });
            const code = await reissueChallenge(db, challenge, ch);
            await sendCodeEmail(ch.email, ch.data.name, code);
            return response.status(200).json({ status: 'ok', sentTo: 'email' });
        }

        // ── РЕГИСТРАЦИЯ, шаг 2: код верный — создаём аккаунт и первый сеанс ──
        if (action === 'registerVerify' && request.method === 'POST') {
            const { challenge, code } = readBody(request);
            const ch = await checkChallenge(db, challenge, 'register', code);
            const emailLower = ch.email, d = ch.data;
            // Пока человек вводил код, кто-то мог занять почту или ник
            if (await db('SISMEMBER', 'all_users', emailLower) === 1)
                return response.status(400).json({ status: 'error', message: 'Этот email уже зарегистрирован' });
            if (await db('GET', `nick:${d.nickname}`))
                return response.status(400).json({ status: 'error', message: 'Этот никнейм уже занят. Начните заново.' });

            await db('SADD', 'all_users', emailLower);
            const userId = await generateUniqueUserId(db);
            await db('HSET', `profile:${emailLower}`,
                'name', d.name, 'nickname', d.nickname, 'avColor', d.avColor,
                'password', d.passHash, 'salt', d.salt, 'userId', userId);
            await db('SET', `id_email:${userId}`, emailLower);
            await db('SET', `nick:${d.nickname}`, emailLower);
            await db('SADD', `user_rooms:${emailLower}`, 'general');
            // Снимаем «надгробную метку», если эта почта раньше уже была удалена
            await db('SREM', 'deleted_users', emailLower);

            const sid = await createSession(db, emailLower, request, 'register');
            await botSend(db, env, emailLower, '👋 Добро пожаловать в GeLink! Это официальный чат GeLink: сюда приходят коды входа и уведомления о входе с новых устройств. Список устройств — в ⚙ → Конфиденциальность → Устройства.');
            const profile = parseHash(await db('HGETALL', `profile:${emailLower}`));
            return response.status(200).json({
                status: 'ok', userId, token: await signToken({ email: emailLower, sid }, env.jwt),
                user: publicUser(emailLower, userId, profile),
            });
        }

        // ── ВХОД, шаг 1: пароль → код (в бота на других устройствах или на почту) ──
        if (action === 'login' && request.method === 'POST') {
            const { email, password } = readBody(request);
            if (!email || !password)
                return response.status(400).json({ status: 'error', message: 'Введите email и пароль' });
            const emailLower = String(email).trim().toLowerCase();
            const wrong = () => response.status(401).json({ status: 'error', message: 'Неверный email или пароль' });

            if (await db('SISMEMBER', 'all_users', emailLower) !== 1) return wrong();
            const profile = parseHash(await db('HGETALL', `profile:${emailLower}`));
            if (!(await checkPassword(db, emailLower, profile, String(password)))) return wrong();

            const { id, code } = await createChallenge(db, 'login', emailLower, {
                device: describeDevice(getHeader(request, 'user-agent')), place: requestPlace(request),
            });
            const others = await liveSessions(db, emailLower);
            const canEmail = !emailLower.endsWith('@users.minva');
            let sentTo;
            if (others.length) {
                // Как в Telegram: если вы уже где-то вошли, код приходит туда — в чат GeLink
                await botSend(db, env, emailLower, `🔐 Код для входа в GeLink: ${code}\n\nКто-то (надеемся, вы) входит в аккаунт: ${describeDevice(getHeader(request, 'user-agent'))}${requestPlace(request) ? ', ' + requestPlace(request) : ''}.\nНикому не сообщайте этот код. Если это не вы — смените пароль.`, { loginCode: true });
                sentTo = 'app';
            } else if (canEmail) {
                await sendCodeEmail(emailLower, profile.name, code);
                sentTo = 'email';
            } else {
                return response.status(400).json({ status: 'error', message: 'Этот аккаунт создан через Minva — войдите кнопкой «Войти через Minva».' });
            }
            return response.status(200).json({ status: 'code_required', challenge: id, sentTo, canEmail, email: canEmail ? maskEmail(emailLower) : null });
        }

        // «Отправить код на почту» / «Отправить ещё раз»
        if (action === 'loginResend' && request.method === 'POST') {
            const { challenge, channel } = readBody(request);
            const ch = await loadChallenge(db, challenge, 'login');
            if (!ch) return response.status(400).json({ status: 'error', message: 'Вход устарел. Введите пароль ещё раз.' });
            const code = await reissueChallenge(db, challenge, ch);
            if (channel === 'email' && !ch.email.endsWith('@users.minva')) {
                const profile = parseHash(await db('HGETALL', `profile:${ch.email}`));
                await sendCodeEmail(ch.email, profile.name, code);
                return response.status(200).json({ status: 'ok', sentTo: 'email', email: maskEmail(ch.email) });
            }
            await botSend(db, env, ch.email, `🔐 Код для входа в GeLink: ${code}\n\nНикому не сообщайте этот код.`, { loginCode: true });
            return response.status(200).json({ status: 'ok', sentTo: 'app' });
        }

        // ── ВХОД, шаг 2: код верный — создаём сеанс ──
        if (action === 'loginVerify' && request.method === 'POST') {
            const { challenge, code } = readBody(request);
            const ch = await checkChallenge(db, challenge, 'login', code);
            const emailLower = ch.email;
            const profile = parseHash(await db('HGETALL', `profile:${emailLower}`));
            if (!profile.nickname && !profile.name)
                return response.status(400).json({ status: 'error', message: 'Аккаунт не найден' });
            const userId = profile.userId || await getUserId(db, emailLower);
            const sid = await createSession(db, emailLower, request, 'password');
            const sess = parseHash(await db('HGETALL', `sess:${sid}`));
            await botSend(db, env, emailLower, `✅ Новый вход в аккаунт: ${sess.device}${sess.place ? ', ' + sess.place : ''}, ${fmtWhen(sess.created)}.\nЕсли это были не вы — завершите этот сеанс в ⚙ → Конфиденциальность → Устройства и смените пароль.`);
            return response.status(200).json({
                status: 'ok', token: await signToken({ email: emailLower, sid }, env.jwt),
                user: publicUser(emailLower, userId, profile),
            });
        }

        // ── ВОССТАНОВЛЕНИЕ ПАРОЛЯ: почта → код → новый пароль ──
        if (action === 'resetStart' && request.method === 'POST') {
            const emailLower = String(readBody(request).email || '').trim().toLowerCase();
            if (!emailLower || await db('SISMEMBER', 'all_users', emailLower) !== 1)
                return response.status(404).json({ status: 'error', message: 'На эту почту не зарегистрирован аккаунт GeLink.' });
            if (emailLower.endsWith('@users.minva'))
                return response.status(400).json({ status: 'error', message: 'Этот аккаунт создан через Minva — войдите кнопкой «Войти через Minva».' });
            const profile = parseHash(await db('HGETALL', `profile:${emailLower}`));
            const { id, code } = await createChallenge(db, 'reset', emailLower);
            await sendCodeEmail(emailLower, profile.name, code);
            return response.status(200).json({ status: 'ok', challenge: id, email: maskEmail(emailLower) });
        }

        if (action === 'resetVerify' && request.method === 'POST') {
            const { challenge, code } = readBody(request);
            const ch = await checkChallenge(db, challenge, 'reset', code);
            const resetToken = randomHex(24);
            await db('SET', `reset_ok:${resetToken}`, ch.email, 'EX', CODE_TTL_SEC);
            return response.status(200).json({ status: 'ok', resetToken });
        }

        if (action === 'resetFinish' && request.method === 'POST') {
            const { resetToken, password, e2eBackup } = readBody(request);
            const emailLower = resetToken ? await db('GETDEL', `reset_ok:${resetToken}`) : null;
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Время на смену пароля вышло. Начните заново.' });
            if (String(password || '').length < 8)
                return response.status(400).json({ status: 'error', message: 'Пароль слишком короткий!' });
            const salt = generateSalt();
            const fields = ['password', await hashPassword(String(password), salt), 'salt', salt];
            if (e2eBackup) fields.push('e2eBackup', e2eBackup);
            await db('HSET', `profile:${emailLower}`, ...fields);
            await db('HDEL', `profile:${emailLower}`, 'minvaOnly');
            // Пароль сброшен — выходим со ВСЕХ устройств: если аккаунт угнали, угонщик вылетит
            for (const s of await liveSessions(db, emailLower)) await endSession(db, emailLower, s.sid);
            await botSend(db, env, emailLower, '🔑 Пароль восстановлен по коду из письма. Все устройства вышли из аккаунта — войдите заново с новым паролем.');
            return response.status(200).json({ status: 'ok' });
        }

        // ── Код для смены пароля в профиле (на почту; аккаунтам без почты — в чат GeLink) ──
        if (action === 'passwordCode' && request.method === 'POST') {
            const me = await authenticate();
            const profile = parseHash(await db('HGETALL', `profile:${me.email}`));
            // Новый пароль совпадает с текущим — код не шлём, менять нечего
            const { password: newPassword } = readBody(request);
            if (newPassword && await checkPassword(db, me.email, profile, String(newPassword)))
                return response.status(400).json({ status: 'error', code: 'same_password', message: 'Новый пароль совпадает с текущим. Придумайте другой.' });
            const { id, code } = await createChallenge(db, 'password', me.email);
            if (me.email.endsWith('@users.minva')) {
                await botSend(db, env, me.email, `🔐 Код для смены пароля: ${code}\n\nНикому не сообщайте этот код.`, { loginCode: true });
                return response.status(200).json({ status: 'ok', challenge: id, sentTo: 'app' });
            }
            await sendCodeEmail(me.email, profile.name, code);
            return response.status(200).json({ status: 'ok', challenge: id, sentTo: 'email', email: maskEmail(me.email) });
        }

        // ══════════════════════════════════════════════════════
        //  ЧЁРНЫЙ СПИСОК
        // ══════════════════════════════════════════════════════
        if (action === 'blockUser' && request.method === 'POST') {
            const me = await authenticate();
            const target = String(readBody(request).target || '').trim().toLowerCase();
            if (!target || target === me.email || await db('SISMEMBER', 'all_users', target) !== 1)
                return response.status(400).json({ status: 'error', message: 'Пользователь не найден' });
            await db('SADD', `blocked:${me.email}`, target);
            await db('HDEL', `contact_requests:${me.email}`, target); // его заявка в контакты больше не висит
            return response.status(200).json({ status: 'ok' });
        }

        if (action === 'unblockUser' && request.method === 'POST') {
            const me = await authenticate();
            const target = String(readBody(request).target || '').trim().toLowerCase();
            await db('SREM', `blocked:${me.email}`, target);
            return response.status(200).json({ status: 'ok' });
        }

        if (action === 'blockedList') {
            const me = await authenticate();
            const emails = (await db('SMEMBERS', `blocked:${me.email}`)) ?? [];
            const users = [];
            for (const e of emails) {
                const p = parseHash(await db('HGETALL', `profile:${e}`));
                users.push({ email: e, name: p.name || e, nickname: p.nickname || '', avImg: p.avImg || null,
                    avColor: p.avColor || 'var(--ge-accent-gradient)', deleted: !p.name && !p.nickname });
            }
            return response.status(200).json({ status: 'ok', users });
        }

        // ══════════════════════════════════════════════════════
        //  GIF: поиск через GIPHY и избранные GIF
        // ══════════════════════════════════════════════════════
        // Ключ GIPHY хранится только на сервере (переменная GIPHY_API_KEY), браузер его не видит.
        // Tenor с 30.06.2026 закрыт для сторонних приложений, поэтому GIPHY.
        if (action === 'gifSearch') {
            await authenticate();
            const key = process.env.GIPHY_API_KEY;
            if (!key) return response.status(503).json({ status: 'error', code: 'no_gif_key', message: 'Поиск GIF ещё не настроен' });
            const q = (request.query.q ?? '').toString().trim().slice(0, 80);
            const offset = Math.max(0, Math.min(4900, parseInt(request.query.offset, 10) || 0));
            const url = new URL(`https://api.giphy.com/v1/gifs/${q ? 'search' : 'trending'}`);
            url.searchParams.set('api_key', key);
            url.searchParams.set('limit', '24');
            url.searchParams.set('offset', String(offset));
            url.searchParams.set('rating', 'pg-13');
            if (q) { url.searchParams.set('q', q); url.searchParams.set('lang', /[а-яё]/i.test(q) ? 'ru' : 'en'); }
            let data;
            try {
                const r = await fetch(url.toString());
                data = await r.json();
                if (!r.ok) throw new Error(data?.meta?.msg || r.status);
            } catch (e) {
                return response.status(502).json({ status: 'error', message: 'GIPHY не ответил, попробуйте ещё раз' });
            }
            const gifs = (data.data || []).map(g => {
                const im = g.images || {};
                const orig = im.original || {};
                const small = im.fixed_width || {};
                const big = (orig.mp4 && Number(orig.mp4_size || 0) < 2.5e6) ? orig : (im.fixed_height || small);
                return {
                    preview: small.mp4 || small.url || null,
                    src: big.mp4 || big.url || null,
                    w: Number(big.width) || Number(small.width) || 200,
                    h: Number(big.height) || Number(small.height) || 200,
                };
            }).filter(g => g.preview && g.src);
            const total = data.pagination?.total_count ?? 0;
            return response.status(200).json({ status: 'ok', gifs, next: offset + 24 < Math.min(total, 4999) ? offset + 24 : null });
        }

        // Избранные GIF: хэш gif_favs:<email>, поле — id (хэш содержимого, считает браузер),
        // значение — данные GIF, зашифрованные ключом самого пользователя (сервер их не видит).
        const GIF_FAVS_MAX = 200;
        if (action === 'gifFavList') {
            const me = await authenticate();
            const items = parseHash(await db('HGETALL', `gif_favs:${me.email}`));
            return response.status(200).json({ status: 'ok', items: Object.entries(items).map(([id, enc]) => ({ id, enc })) });
        }
        if (action === 'gifFavAdd' && request.method === 'POST') {
            const me = await authenticate();
            const id = String(request.body?.id ?? '');
            const enc = String(request.body?.enc ?? '');
            if (!/^[a-f0-9]{16,64}$/.test(id) || !enc) return response.status(400).json({ status: 'error', message: 'Неверные данные' });
            if (enc.length > 2_000_000) return response.status(413).json({ status: 'error', message: 'GIF слишком большой для избранного' });
            const have = parseHash(await db('HGETALL', `gif_favs:${me.email}`));
            if (!(id in have) && Object.keys(have).length >= GIF_FAVS_MAX)
                return response.status(400).json({ status: 'error', message: `В избранном уже ${GIF_FAVS_MAX} GIF — удалите какие-нибудь` });
            await db('HSET', `gif_favs:${me.email}`, id, enc);
            return response.status(200).json({ status: 'ok' });
        }
        if (action === 'gifFavRemove' && request.method === 'POST') {
            const me = await authenticate();
            await db('HDEL', `gif_favs:${me.email}`, String(request.body?.id ?? ''));
            return response.status(200).json({ status: 'ok' });
        }

        // ══════════════════════════════════════════════════════
        //  УСТРОЙСТВА (активные сеансы)
        // ══════════════════════════════════════════════════════
        // Новое устройство первые 24 часа не может завершать другие сеансы — как в Telegram.
        // Если аккаунт угнали, угонщик не сможет сразу выкинуть настоящего владельца.
        const terminateRule = me => {
            const unlockAt = Number(me.session.created || 0) + NEW_SESSION_LOCK;
            return { canTerminate: Date.now() >= unlockAt, canTerminateAt: unlockAt };
        };

        if (action === 'sessionsList') {
            const me = await authenticate();
            const list = (await liveSessions(db, me.email))
                .map(s => ({
                    sid: s.sid, device: s.device || 'Неизвестное устройство', place: s.place || '', ip: s.ip || '',
                    created: Number(s.created || 0), lastSeen: Number(s.lastSeen || 0), via: s.via || 'password',
                    current: s.sid === me.sid,
                }))
                .sort((a, b) => (b.current - a.current) || (b.lastSeen - a.lastSeen));
            return response.status(200).json({ status: 'ok', sessions: list, ...terminateRule(me), now: Date.now() });
        }

        if (action === 'sessionTerminate' && request.method === 'POST') {
            const me = await authenticate();
            const { sid } = readBody(request);
            if (!sid) return response.status(400).json({ status: 'error', message: 'Не указан сеанс' });
            if (sid !== me.sid) {
                const rule = terminateRule(me);
                if (!rule.canTerminate)
                    return response.status(403).json({ status: 'error', code: 'too_new', ...rule,
                        message: 'С нового устройства нельзя завершать другие сеансы первые 24 часа после входа.' });
                const target = parseHash(await db('HGETALL', `sess:${sid}`));
                if (target.email !== me.email) return response.status(404).json({ status: 'error', message: 'Сеанс уже завершён' });
            }
            await endSession(db, me.email, sid);
            return response.status(200).json({ status: 'ok' });
        }

        if (action === 'sessionTerminateOthers' && request.method === 'POST') {
            const me = await authenticate();
            const rule = terminateRule(me);
            if (!rule.canTerminate)
                return response.status(403).json({ status: 'error', code: 'too_new', ...rule,
                    message: 'С нового устройства нельзя завершать другие сеансы первые 24 часа после входа.' });
            let ended = 0;
            for (const s of await liveSessions(db, me.email)) {
                if (s.sid !== me.sid) { await endSession(db, me.email, s.sid); ended++; }
            }
            return response.status(200).json({ status: 'ok', ended });
        }

        if (action === 'logout' && request.method === 'POST') {
            const me = await authenticate();
            await endSession(db, me.email, me.sid);
            return response.status(200).json({ status: 'ok' });
        }

        // ══════════════════════════════════════════════════════
        //  ОБНОВЛЕНИЕ ПРОФИЛЯ
        //  Берём email: сначала из JWT (если есть), иначе из query
        // ══════════════════════════════════════════════════════
        if (action === 'updateProfile' && request.method === 'POST') {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            const { name, nickname, avColor, password, avImg, bio, pubKey, e2eBackup, pwChallenge, pwCode } = request.body;
            const fields = [];

            // Смена пароля — только с кодом (action=passwordCode): иначе тот, кто завладел
            // открытым устройством, мог бы сменить пароль и забрать аккаунт.
            if (password) {
                const current = parseHash(await db('HGETALL', `profile:${emailLower}`));
                if (await checkPassword(db, emailLower, current, String(password)))
                    return response.status(400).json({ status: 'error', code: 'same_password', message: 'Новый пароль совпадает с текущим. Придумайте другой.' });
                const ch = await checkChallenge(db, pwChallenge, 'password', pwCode);
                if (ch.email !== emailLower) throw Object.assign(new Error('Код устарел. Запросите новый.'), { status: 400 });
            }
            if (nickname) {
                const owner = await db('GET', `nick:${String(nickname).toLowerCase()}`);
                if (owner && owner !== emailLower)
                    return response.status(409).json({ status: 'error', message: 'Этот никнейм уже занят' });
            }

            if (name)     fields.push('name',     name);
            if (avColor)  fields.push('avColor',  avColor);
            if (pubKey)   fields.push('pubKey',   pubKey); // публичный ключ E2E-шифрования (можно переиздавать)
            if (e2eBackup) fields.push('e2eBackup', e2eBackup); // резервная копия приватного ключа, зашифрованная паролем — сервер расшифровать её не может
            if (password) {
                const newSalt = generateSalt();
                fields.push('password', await hashPassword(password, newSalt), 'salt', newSalt);
                await db('HDEL', `profile:${emailLower}`, 'minvaOnly'); // пароль задан — Minva больше не единственный вход
            }
            if (bio !== undefined) fields.push('bio', (bio || '').toString().slice(0, 150));

            if (nickname) {
                const nickLower = nickname.toLowerCase();
                const oldNick   = await db('HGET', `profile:${emailLower}`, 'nickname');
                if (oldNick) await db('DEL', `nick:${oldNick}`);
                fields.push('nickname', nickLower);
                await db('SET', `nick:${nickLower}`, emailLower);
            }

            if (avImg !== undefined) {
                if (avImg) fields.push('avImg', avImg);
                else await db('HDEL', `profile:${emailLower}`, 'avImg');
            }

            if (fields.length > 0) await db('HSET', `profile:${emailLower}`, ...fields);
            if (password) await botSend(db, env, emailLower, `🔑 Пароль от вашего аккаунта изменён (${(await authenticate()).session.device}). Если это были не вы — срочно восстановите пароль и завершите чужие сеансы в ⚙ → Конфиденциальность → Устройства.`);
            return response.status(200).json({ status: 'ok' });
        }

        // Полное удаление аккаунта — реально стирает данные пользователя (не косметика)
        if (action === 'deleteAccount') {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            // ВАЖНО: всё, что ниже до финального блока — это best-effort уборка (чужие
            // контакты, уведомления групп и т.п.). Раньше, если тут что-то падало
            // с ошибкой, весь обработчик прерывался ДО того, как реально стереть профиль
            // и email из all_users — аккаунт оставался "наполовину удалённым", и повторная
            // регистрация с той же почтой вечно говорила "уже зарегистрирован". Теперь
            // каждый необязательный шаг обёрнут отдельно и не может заблокировать финал.

            // Отвязываемся от контактов — убираем себя из ЧУЖИХ списков контактов тоже,
            // и, что важно, убираем сам приватный чат из их списка комнат — иначе удалённый
            // аккаунт продолжал "висеть" у контакта в списке чатов вечно.
            try {
                const myContacts = (await db('SMEMBERS', `contacts:${emailLower}`)) ?? [];
                const myUserId = await getUserId(db, emailLower);
                const myOldSafe = emailLower.replace(/[@.]/g, '');
                await Promise.all(myContacts.map(async c => {
                    try {
                        await db('SREM', `contacts:${c}`, emailLower);
                        const otherUserId = await getUserId(db, c);
                        const roomId = `private-${[myUserId, otherUserId].sort().join('-')}`;
                        await db('SREM', `user_rooms:${c}`, roomId);
                        // На случай, если у этой пары ещё осталась комната по СТАРОЙ схеме
                        // (на основе email, до перехода на userId) — чистим и её тоже.
                        const oldRoomId = `private-${[myOldSafe, c.replace(/[@.]/g, '')].sort().join('-')}`;
                        if (oldRoomId !== roomId) await db('SREM', `user_rooms:${c}`, oldRoomId);
                        await db('HDEL', `contact_requests:${c}`, emailLower);
                    } catch {}
                }));
            } catch {}

            // Выходим из всех групп, в которых состоим, и уведомляем остальных участников
            try {
                const myName = (await db('HGET', `profile:${emailLower}`, 'name')) || emailLower;
                const myRooms = (await db('SMEMBERS', `user_rooms:${emailLower}`)) ?? [];
                await Promise.all(
                    myRooms
                        .filter(r => r !== 'general' && !r.startsWith('private-'))
                        .map(async r => {
                            try {
                                await db('SREM', `group_members:${r}`, emailLower);
                                const stillExists = await db('EXISTS', `group:${r}`);
                                if (stillExists) await pushSystemMessage(db, r, `${myName} покинул(а) группу (аккаунт удалён)`, emailLower, env);
                            } catch {}
                        })
                );
            } catch {}

            // Освобождаем никнейм
            try {
                const nickname = await db('HGET', `profile:${emailLower}`, 'nickname');
                if (nickname) await db('DEL', `nick:${nickname}`);
            } catch {}

            try {
                await db('DEL', `contact_requests:${emailLower}`);
            } catch {}

            try {
                const minvaSub = await db('HGET', `profile:${emailLower}`, 'minvaSub');
                if (minvaSub) await db('DEL', `minva_sub:${minvaSub}`);
            } catch {}
            // Все сеансы, чёрный список и служебный чат GeLink этого аккаунта
            try { await db('DEL', `blocked:${emailLower}`); } catch {}
            try { await db('DEL', `gif_favs:${emailLower}`); } catch {}
            try {
                for (const sid of (await db('SMEMBERS', `user_sessions:${emailLower}`)) ?? []) await db('DEL', `sess:${sid}`);
                await db('DEL', `user_sessions:${emailLower}`);
                const uid = await db('HGET', `profile:${emailLower}`, 'userId');
                if (uid) await db('DEL', `room:${botRoomFor(uid)}`);
            } catch {}

            // ── КРИТИЧНАЯ ЧАСТЬ — должна выполниться, что бы ни случилось выше ──
            await db('DEL', `contacts:${emailLower}`);
            await db('DEL', `user_rooms:${emailLower}`);
            await db('DEL', `profile:${emailLower}`);
            await db('SREM', 'all_users', emailLower);
            // "Надгробная метка" — позволяет findUser сказать контактам "Аккаунт удалён"
            // вместо того, чтобы чат просто зависал без объяснений. Снимается автоматически
            // при повторной регистрации той же почты (см. action=register).
            await db('SADD', 'deleted_users', emailLower);

            return response.status(200).json({ status: 'ok' });
        }

        // ══════════════════════════════════════════════════════
        //  ПРИСУТСТВИЕ (онлайн/офлайн) — короткий "пинг" от клиента, пока
        //  приложение открыто и активно. Статус "в сети" — это ПРОСТО наличие
        //  свежей записи с TTL: если пинги перестают приходить (закрыли вкладку,
        //  разрядился телефон, упала сеть), запись сама истечёт через 40 секунд
        //  и человек автоматически станет "не в сети" — отдельно помечать выход
        //  из сети не нужно, TTL делает это сам.
        // ══════════════════════════════════════════════════════
        if (action === 'heartbeat') {
            const emailLower = await tryAuth(request, env.jwt);
            await db('SET', `last_seen:${emailLower}`, String(Date.now()), 'EX', 40);
            return response.status(200).json({ status: 'ok' });
        }

        // ══════════════════════════════════════════════════════
        //  СОХРАНЕНИЕ ПРОФИЛЯ  — публичный (вызывается после OTP)
        // ══════════════════════════════════════════════════════
        if (action === 'saveProfile' && request.method === 'POST') {
            const user_email = await tryAuth(request, env.jwt);
            const { nickname, name, pubKey } = request.body;
            await db('SADD', 'all_users', user_email);
            await db('SADD', `user_rooms:${user_email}`, 'general'); // добавляем в general
            if (name)     await db('HSET', `profile:${user_email}`, 'name', name);
            if (pubKey)   await db('HSET', `profile:${user_email}`, 'pubKey', pubKey);
            if (nickname) {
                const nickLower = String(nickname).toLowerCase();
                // Ник можно занять, только если он свободен или уже наш — нельзя забрать чужой
                const owner = await db('GET', `nick:${nickLower}`);
                if (!owner || owner === user_email) {
                    await db('HSET', `profile:${user_email}`, 'nickname', nickLower);
                    await db('SET',  `nick:${nickLower}`, user_email);
                }
            }
            return response.status(200).json({ status: 'ok' });
        }

        // ══════════════════════════════════════════════════════
        //  WebRTC СИГНАЛИЗАЦИЯ
        // ══════════════════════════════════════════════════════
        if (action === 'signal' && request.method === 'POST') {
            const body = readBody(request);
            const { to } = body;
            if (!to) return response.status(400).json({ status: 'error' });
            body.from = await tryAuth(request, env.jwt); // нельзя подписаться чужим адресом
            if (await isBlockedBy(db, String(to).toLowerCase(), body.from) || await isBlockedBy(db, body.from, String(to).toLowerCase()))
                return response.status(200).json({ status: 'ok' }); // звонок просто не доходит
            await db('LPUSH', `signal:${to}`, JSON.stringify(body));
            await db('EXPIRE', `signal:${to}`, 60);
            return response.status(200).json({ status: 'ok' });
        }

        if (action === 'getSignals') {
            // email: из JWT если есть, иначе из query (старый фронт)
            const email = await tryAuth(request, env.jwt);
            if (!email) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            const key     = `signal:${email}`;
            const raw     = await db('LRANGE', key, 0, -1);
            await db('DEL', key);
            const signals = (raw ?? []).map(s => { try { return JSON.parse(s); } catch { return null; } }).filter(Boolean);
            return response.status(200).json({ status: 'ok', signals });
        }

        // ══════════════════════════════════════════════════════
        //  ПОИСК ПОЛЬЗОВАТЕЛЯ  — публичный
        // ══════════════════════════════════════════════════════
        if (action === 'findUser' && request.query.query) {
            let q = request.query.query.trim().toLowerCase();

            // Если запрос — это userId (а не email/ник), резолвим его в реальный email
            // через обратный индекс. Это нужно потому, что id личной комнаты теперь
            // строится из userId, а не email — чтобы понять, с кем именно этот чат,
            // клиенту нужно уметь искать профиль напрямую по userId.
            const emailByUserId = await db('GET', `id_email:${q}`);
            if (emailByUserId) q = emailByUserId;

            const viewer = await tryAuth(request, env.jwt).catch(() => null);
            const byEmail = await db('SISMEMBER', 'all_users', q);
            if (byEmail === 1) {
                // userId (для id личной комнаты) и online (есть ли свежий пинг) — внутри publicProfile
                return response.status(200).json({ status: 'found', email: q, profile: await publicProfile(db, q, viewer) });
            }

            // Аккаунт мог быть удалён владельцем — отдаём явный признак "deleted",
            // чтобы у контактов чат не зависал вечно на "Загрузка…"/пустом профиле,
            // а сразу показывал понятное "Аккаунт удалён".
            if (await db('SISMEMBER', 'deleted_users', q) === 1) {
                return response.status(200).json({ status: 'found', email: q, profile: { deleted: '1' } });
            }

            // Раз не email — возможно, это никнейм
            const foundEmail = await db('GET', `nick:${q}`);
            if (!foundEmail)
                return response.status(404).json({ status: 'error', message: 'User not found' });

            return response.status(200).json({ status: 'found', email: foundEmail, profile: await publicProfile(db, foundEmail, viewer) });
        }

        // Резервная копия приватного E2E-ключа — доступна ТОЛЬКО самому владельцу
        // (проверяем, что запрашивающий — это тот же email, что и цель запроса).
        if (action === 'getE2EBackup' && request.query.query) {
            const jwtEmail = await tryAuth(request, env.jwt);
            const requesterEmail = (jwtEmail ?? '').trim().toLowerCase();
            const targetEmail = request.query.query.trim().toLowerCase();
            if (!requesterEmail || requesterEmail !== targetEmail)
                return response.status(403).json({ status: 'error', message: 'Доступ запрещён' });

            const e2eBackup = await db('HGET', `profile:${targetEmail}`, 'e2eBackup');
            return response.status(200).json({ status: 'ok', e2eBackup: e2eBackup || null });
        }

        // ══════════════════════════════════════════════════════
        //  КОНТАКТЫ
        // ══════════════════════════════════════════════════════
        if (action === 'addContact' && target_email) {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            if (await isBlockedBy(db, emailLower, target_email))
                return response.status(400).json({ status: 'error', message: 'Этот пользователь в вашем чёрном списке. Сначала разблокируйте его.' });
            // Нас заблокировали — делаем вид, что заявка отправлена, но никуда её не кладём
            if (await isBlockedBy(db, target_email, emailLower))
                return response.status(200).json({ status: 'pending' });
            if (await db('SISMEMBER', 'all_users', target_email) !== 1)
                return response.status(404).json({ status: 'error', message: 'User not found' });

            const roomId = await resolvePrivateRoomId(db, emailLower, target_email);

            // Уже в контактах друг у друга — ничего заново отправлять не нужно
            const alreadyContacts = await db('SISMEMBER', `contacts:${emailLower}`, target_email);
            if (alreadyContacts) {
                await db('SADD', `user_rooms:${emailLower}`, roomId);
                return response.status(200).json({ status: 'success', message: 'Contact added', roomId });
            }

            // Если собеседник уже прислал ЗАЯВКУ нам — считаем это взаимным согласием
            // и сразу соединяем (как и во ВК: если оба отправили заявку друг другу)
            const theyAlreadyRequestedMe = await db('HGET', `contact_requests:${emailLower}`, target_email);
            if (theyAlreadyRequestedMe) {
                await db('HDEL', `contact_requests:${emailLower}`, target_email);
                await db('SADD', `contacts:${emailLower}`,   target_email);
                await db('SADD', `user_rooms:${emailLower}`, roomId);
                await db('SADD', `contacts:${target_email}`, emailLower);
                await db('SADD', `user_rooms:${target_email}`, roomId);
                return response.status(200).json({ status: 'success', message: 'Contact added', roomId });
            }

            // Иначе — отправляем заявку получателю, дожидаемся его подтверждения
            await db('HSET', `contact_requests:${target_email}`, emailLower, Date.now());
            return response.status(200).json({ status: 'pending', message: 'Заявка отправлена', roomId });
        }

        // Список входящих заявок в контакты (для уведомления, "как во ВК")
        if (action === 'getContactRequests') {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            const raw = await db('HGETALL', `contact_requests:${emailLower}`);
            const map = parseHash(raw);
            const requests = await Promise.all(Object.entries(map).map(async ([fromEmail, ts]) => {
                const name = await db('HGET', `profile:${fromEmail}`, 'name');
                return { email: fromEmail, name: name || fromEmail, ts: Number(ts) };
            }));
            requests.sort((a, b) => b.ts - a.ts);
            return response.status(200).json({ status: 'ok', requests });
        }

        // Принять заявку в контакты — только теперь оба становятся видны друг другу
        if (action === 'acceptContactRequest' && target_email) {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            const hasRequest = await db('HGET', `contact_requests:${emailLower}`, target_email);
            if (!hasRequest) return response.status(404).json({ status: 'error', message: 'Заявка не найдена' });

            await db('HDEL', `contact_requests:${emailLower}`, target_email);

            const roomId = await resolvePrivateRoomId(db, emailLower, target_email);

            await db('SADD', `contacts:${emailLower}`,   target_email);
            await db('SADD', `user_rooms:${emailLower}`, roomId);
            await db('SADD', `contacts:${target_email}`, emailLower);
            await db('SADD', `user_rooms:${target_email}`, roomId);

            const name = await db('HGET', `profile:${target_email}`, 'name');
            await pushSystemMessage(db, roomId, 'Заявка в контакты принята — теперь вы можете переписываться', emailLower, env);
            return response.status(200).json({ status: 'ok', roomId, name: name || target_email });
        }

        // Отклонить заявку в контакты — просто удаляем её, диалог не создаётся
        if (action === 'declineContactRequest' && target_email) {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            await db('HDEL', `contact_requests:${emailLower}`, target_email);
            return response.status(200).json({ status: 'ok' });
        }

        // Проверка: висит ли ещё МОЯ заявка на добавление target_email в контакты.
        // Нужна клиенту, чтобы не доверять вечно локальной метке "приглашение уже
        // отправлено" (localStorage) — та могла протухнуть (заявку уже приняли/
        // отклонили/контакт удалили заново), а сервер знает актуальное состояние.
        if (action === 'checkPendingInvite' && target_email) {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            const pending = await db('HGET', `contact_requests:${target_email}`, emailLower);
            return response.status(200).json({ status: 'ok', pending: !!pending });
        }

        if (action === 'removeContact' && target_email) {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();

            const roomId = await resolvePrivateRoomId(db, emailLower, target_email);

            // Раньше удаляли контакт только у себя — собеседник продолжал считать нас
            // контактом (у него оставались и contacts, и user_rooms), и мог писать напрямую,
            // хотя должен был снова увидеть "отправить приглашение". Удаляем с обеих сторон.
            await db('SREM', `contacts:${emailLower}`,   target_email);
            await db('SREM', `user_rooms:${emailLower}`, roomId);
            await db('SREM', `contacts:${target_email}`, emailLower);
            await db('SREM', `user_rooms:${target_email}`, roomId);
            return response.status(200).json({ status: 'success', message: 'Contact removed' });
        }

        // ══════════════════════════════════════════════════════
        //  ГРУППЫ
        // ══════════════════════════════════════════════════════

        // Создать группу
        if (action === 'createGroup') {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            const rawName = (request.query.name ?? '').toString().trim();
            if (!rawName) return response.status(400).json({ status: 'error', message: 'Укажите название группы' });
            const name = rawName.slice(0, 60);

            const groupId = await generateUniqueGroupId(db);

            await db('HSET', `group:${groupId}`,
                'name',      name,
                'owner',     emailLower,
                'createdAt', Date.now(),
            );
            await db('SADD', `group_members:${groupId}`, emailLower);
            await db('SADD', `user_rooms:${emailLower}`, groupId);
            await db('SADD', 'all_users', emailLower);

            return response.status(200).json({ status: 'ok', groupId, name });
        }

        // Изменить название и/или аватар группы (только владелец) — видно всем участникам
        if (action === 'updateGroupProfile' && request.method === 'POST') {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            const body = request.body ?? {};
            const groupIdRaw = (body.groupId ?? '').toString().trim();
            if (!groupIdRaw) return response.status(400).json({ status: 'error', message: 'Не указан ID группы' });
            const groupId = groupIdRaw.toUpperCase();

            if (groupId === GENERAL_GROUP_ID) {
                return response.status(403).json({ status: 'error', message: 'Изменить General нельзя' });
            }

            const owner = await db('HGET', `group:${groupId}`, 'owner');
            if (!owner) return response.status(404).json({ status: 'error', message: 'Группа не найдена' });
            if (owner !== emailLower) return response.status(403).json({ status: 'error', message: 'Изменить группу может только владелец' });

            const fields = [];
            if (typeof body.name === 'string' && body.name.trim()) {
                fields.push('name', body.name.trim().slice(0, 60));
            }
            if (body.avImg !== undefined) {
                if (body.avImg) fields.push('avImg', body.avImg);
                else await db('HDEL', `group:${groupId}`, 'avImg');
            }
            if (fields.length > 0) await db('HSET', `group:${groupId}`, ...fields);

            const info = parseHash(await db('HGETALL', `group:${groupId}`));
            return response.status(200).json({
                status: 'ok',
                groupId,
                name: info.name,
                avImg: info.avImg || null,
            });
        }

        // Вступить в группу по ID
        if (action === 'joinGroup' && request.query.groupId) {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            const groupId = request.query.groupId.toString().trim().toUpperCase();

            // Зарезервированный ID 00000000 — это общий канал General, а не отдельная группа.
            // Никакой новой группы не создаём: просто добавляем комнату 'general' пользователю,
            // если он ещё не состоит в ней (повторное вступление не выполняем).
            if (groupId === GENERAL_GROUP_ID) {
                const alreadyMember = !!(await db('SISMEMBER', 'user_rooms:' + emailLower, 'general'));
                if (!alreadyMember) {
                    await db('SADD', `user_rooms:${emailLower}`, 'general');
                    await db('SADD', 'all_users', emailLower);
                }
                return response.status(200).json({
                    status: 'ok',
                    groupId: 'general',
                    name: 'general',
                    alreadyMember,
                });
            }

            const exists  = await db('EXISTS', `group:${groupId}`);
            if (!exists) return response.status(404).json({ status: 'error', message: 'Группа с таким ID не найдена' });

            const info = parseHash(await db('HGETALL', `group:${groupId}`));

            const wasAlreadyMember = !!(await db('SISMEMBER', `group_members:${groupId}`, emailLower));
            await db('SADD', `group_members:${groupId}`, emailLower);
            await db('SADD', `user_rooms:${emailLower}`, groupId);
            await db('SADD', 'all_users', emailLower);

            if (!wasAlreadyMember) {
                const myName = (await db('HGET', `profile:${emailLower}`, 'name')) || emailLower;
                await pushSystemMessage(db, groupId, `${myName} вступил(а) в группу`, emailLower, env);
            }

            const memberCount = await db('SCARD', `group_members:${groupId}`);
            return response.status(200).json({ status: 'ok', groupId, name: info.name, avImg: info.avImg || null, memberCount });
        }

        // Информация о группе (название, кол-во участников; owner виден только владельцу)
        if (action === 'getGroupInfo' && request.query.groupId) {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();

            const groupIdRaw = request.query.groupId.toString().trim();
            const groupId = groupIdRaw.toUpperCase();

            // Общий канал General не хранится в group:* — считаем участников иначе
            // (в него автоматически входят все зарегистрированные пользователи)
            if (groupIdRaw.toLowerCase() === 'general' || groupId === GENERAL_GROUP_ID) {
                const memberCount = await db('SCARD', 'all_users');
                return response.status(200).json({
                    status: 'ok',
                    groupId: 'general',
                    name: 'general',
                    memberCount,
                    isOwner: false,
                    isGeneral: true,
                });
            }

            const exists  = await db('EXISTS', `group:${groupId}`);
            if (!exists) return response.status(404).json({ status: 'error', message: 'Группа не найдена' });

            const info        = parseHash(await db('HGETALL', `group:${groupId}`));
            const memberCount = await db('SCARD', `group_members:${groupId}`);
            const isOwner     = !!emailLower && emailLower === info.owner;

            return response.status(200).json({
                status: 'ok',
                groupId,
                name: info.name,
                memberCount,
                isOwner,
                avImg: info.avImg || null,
            });
        }

        // Покинуть группу (для участников, не владельца)
        // Очистить чат: mode=me — только у себя (остальные видят историю как раньше),
        // mode=all — стереть переписку полностью для обеих сторон (только приватные чаты)
        if (action === 'clearChat' && room) {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            const mode = (request.query.mode || 'me').toString();

            if (mode === 'all') {
                if (!room.startsWith('private-')) {
                    return response.status(403).json({ status: 'error', message: 'Полная очистка доступна только для личных чатов' });
                }
                await db('DEL', `room:${room}`);
                await db('DEL', `room_cleared:${room}`);
                return response.status(200).json({ status: 'ok', mode: 'all' });
            }

            // mode 'me' — помечаем время, раньше которого сообщения скрываются только у нас
            await db('HSET', `room_cleared:${room}`, emailLower, Date.now());
            return response.status(200).json({ status: 'ok', mode: 'me' });
        }

        if (action === 'leaveGroup' && request.query.groupId) {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            const groupId = request.query.groupId.toString().trim().toUpperCase();

            const wasMember = !!(await db('SISMEMBER', `group_members:${groupId}`, emailLower));
            await db('SREM', `group_members:${groupId}`, emailLower);
            await db('SREM', `user_rooms:${emailLower}`, groupId);

            // Сообщение о выходе публикуем, только если группа ещё существует
            // (её не удалили только что владелец) и человек реально в ней состоял
            if (wasMember) {
                const stillExists = await db('EXISTS', `group:${groupId}`);
                if (stillExists) {
                    const myName = (await db('HGET', `profile:${emailLower}`, 'name')) || emailLower;
                    await pushSystemMessage(db, groupId, `${myName} покинул(а) группу`, emailLower, env);
                }
            }

            return response.status(200).json({ status: 'ok' });
        }

        // Удалить группу навсегда — только владелец: чистим сообщения, участников, освобождаем ID
        if (action === 'deleteGroup' && request.query.groupId) {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            const groupId = request.query.groupId.toString().trim().toUpperCase();

            // ID 00000000 зарезервирован за General — его нельзя удалить ни при каких условиях
            if (groupId === GENERAL_GROUP_ID) {
                return response.status(403).json({ status: 'error', message: 'ID 00000000 зарезервирован и не может быть удалён' });
            }

            const owner    = await db('HGET', `group:${groupId}`, 'owner');
            if (!owner) return response.status(404).json({ status: 'error', message: 'Группа не найдена' });
            if (owner !== emailLower) return response.status(403).json({ status: 'error', message: 'Удалить группу может только владелец' });

            const members = (await db('SMEMBERS', `group_members:${groupId}`)) ?? [];
            await Promise.all(members.map(m => db('SREM', `user_rooms:${m}`, groupId)));

            await db('DEL', `group_members:${groupId}`);
            await db('DEL', `group:${groupId}`);
            await db('DEL', `room:${groupId}`); // удаляем все сообщения группы

            return response.status(200).json({ status: 'ok' });
        }

        // Сменить ID группы (только владелец): старый ID полностью освобождается,
        // новый выдаётся так же, как при создании. Сообщения и участники переносятся.
        if (action === 'changeGroupId' && request.query.groupId) {
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = (jwtEmail ?? '').trim().toLowerCase();
            if (!emailLower) return response.status(400).json({ status: 'error', message: 'Не указан email' });

            const oldId = request.query.groupId.toString().trim().toUpperCase();

            // ID 00000000 зарезервирован за General — его нельзя менять
            if (oldId === GENERAL_GROUP_ID) {
                return response.status(403).json({ status: 'error', message: 'ID 00000000 зарезервирован и не может быть изменён' });
            }

            const owner = await db('HGET', `group:${oldId}`, 'owner');
            if (!owner) return response.status(404).json({ status: 'error', message: 'Группа не найдена' });
            if (owner !== emailLower) return response.status(403).json({ status: 'error', message: 'Сменить ID может только владелец' });

            const name  = await db('HGET', `group:${oldId}`, 'name');
            const avImg = await db('HGET', `group:${oldId}`, 'avImg');
            const newId = await generateUniqueGroupId(db);

            // Переносим метаданные и участников группы под новым ключом
            await db('RENAME', `group:${oldId}`, `group:${newId}`);
            await db('RENAME', `group_members:${oldId}`, `group_members:${newId}`);
            // Сообщения переносим, только если они вообще есть (RENAME падает на несуществующем ключе)
            const hasMessages = await db('EXISTS', `room:${oldId}`);
            if (hasMessages) await db('RENAME', `room:${oldId}`, `room:${newId}`);

            // У всех участников заменяем старый ID на новый в их списке комнат
            const members = (await db('SMEMBERS', `group_members:${newId}`)) ?? [];
            await Promise.all(members.map(async m => {
                await db('SREM', `user_rooms:${m}`, oldId);
                await db('SADD', `user_rooms:${m}`, newId);
            }));

            const memberCount = await db('SCARD', `group_members:${newId}`);
            return response.status(200).json({ status: 'ok', oldId, newId, name, avImg: avImg || null, memberCount });
        }

        // ══════════════════════════════════════════════════════
        //  ОТПРАВИТЬ СООБЩЕНИЕ
        // ══════════════════════════════════════════════════════
        if (request.method === 'POST') {
            const body       = request.body;
            const jwtEmail   = await tryAuth(request, env.jwt);
            const emailLower = jwtEmail ?? '';

            // В официальный чат GeLink пишет только сервер
            if (room.startsWith(BOT_ROOM_PREFIX))
                return response.status(403).json({ status: 'error', message: 'Это служебный чат GeLink — отвечать в него нельзя' });

            // Если это приватный чат — отправитель должен уже состоять в этой комнате
            // (т.е. быть реальным контактом собеседника). private-комната добавляется в
            // user_rooms только через addContact/acceptContactRequest, так что этой проверки
            // достаточно, чтобы нельзя было слать сообщения (текст, фото, файлы, голосовые,
            // видеосообщения — всё идёт через этот же путь) человеку, который не в контактах,
            // в обход интерфейса (например, напрямую через API).
            if (room.startsWith('private-') && emailLower) {
                const isMember = await db('SISMEMBER', `user_rooms:${emailLower}`, room);
                if (!isMember) {
                    return response.status(403).json({ status: 'error', message: 'Нельзя писать пользователю, который не в контактах' });
                }
                const peer = await privatePeerEmail(db, room, emailLower);
                if (peer && await isBlockedBy(db, emailLower, peer))
                    return response.status(403).json({ status: 'error', code: 'you_blocked', message: 'Этот пользователь в вашем чёрном списке. Разблокируйте его, чтобы написать.' });
                if (peer && await isBlockedBy(db, peer, emailLower))
                    return response.status(403).json({ status: 'error', code: 'blocked_you', message: 'Сообщение не доставлено: пользователь ограничил получение сообщений от вас.' });
            }

            // Если это настоящая группа (не general, не приватный чат) — проверяем, что она
            // ещё существует. Иначе сообщение "воскрешало" удалённую группу: сервер молча
            // принимал его и заново добавлял комнату в user_rooms отправителя.
            const isRealGroupRoom = room !== 'general' && !room.startsWith('private-');
            if (isRealGroupRoom) {
                const groupExists = await db('EXISTS', `group:${room}`);
                if (!groupExists) {
                    return response.status(410).json({ status: 'error', message: 'Группа была удалена', groupDeleted: true });
                }
            }

            // body может прийти как строка (старый фронт) или объект (новый)
            const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
            await db('LPUSH', `room:${room}`, await encryptForStorage(bodyStr, env));

            // Добавляем в all_users/user_rooms ТОЛЬКО если профиль реально существует.
            // Раньше это делалось безусловно для любого email, который пришёл в запросе —
            // из-за этого удалённый аккаунт "воскресал": фоновый опрос/отправка сообщения,
            // ушедшие в сеть ДО удаления, но обработанные сервером ПОСЛЕ, возвращали email
            // обратно в all_users, и повторная регистрация с той же почтой блокировалась
            // ("email уже зарегистрирован"), хотя профиль уже был стёрт.
            if (emailLower) {
                const profileExists = await db('EXISTS', `profile:${emailLower}`);
                if (profileExists) {
                    await db('SADD', 'all_users', emailLower);
                    if (!room.startsWith('private-')) {
                        await db('SADD', `user_rooms:${emailLower}`, room);
                    }
                }
            }
            return response.status(200).json({ status: 'ok' });
        }

        // ══════════════════════════════════════════════════════
        //  ЗАГРУЗИТЬ СООБЩЕНИЯ + КОМНАТЫ + КОНТАКТЫ
        // ══════════════════════════════════════════════════════
        const jwtEmail   = await tryAuth(request, env.jwt);
        const emailLower = (jwtEmail ?? '').trim().toLowerCase();

        // Читать комнату может только её участник (раньше любой мог прочитать любую комнату,
        // зная её id). Чужие/удалённые комнаты просто отдаются пустыми — интерфейс не ломается.
        const canRead = room === 'general' || await db('SISMEMBER', `user_rooms:${emailLower}`, room) === 1;
        let messages = canRead ? await db('LRANGE', `room:${room}`, 0, 50) : [];
        // Расшифровываем сразу после чтения — дальше по коду (фильтр "очистить у
        // себя" ниже, и то, что видит фронт) всё работает с уже привычной,
        // нешифрованной обёрткой (encodeURIComponent от JSON), как и раньше.
        if (Array.isArray(messages) && messages.length) {
            messages = await Promise.all(messages.map(raw => decryptStoredMessage(raw, env)));
        }

        let rooms    = { result: [] };
        let contacts = { result: [] };
        let reads    = {};

        if (emailLower) {
            // Та же защита от "воскрешения" удалённого аккаунта, что и в обработчике
            // отправки сообщений выше: не трогаем all_users/user_rooms, если профиля
            // уже не существует (аккаунт был удалён).
            const profileExists = await db('EXISTS', `profile:${emailLower}`);
            if (profileExists) {
            await db('SADD', 'all_users', emailLower);
            await db('SADD', `user_rooms:${emailLower}`, 'general'); // всегда в general

            // Раз мы загружаем сообщения этой комнаты — значит, пользователь её сейчас
            // просматривает. Отмечаем время прочтения и возвращаем отметки всех участников,
            // чтобы отправитель видел двойную галочку, когда получатель прочитал сообщение.
            if (canRead) await db('HSET', `room_reads:${room}`, emailLower, Date.now());

            const [rawRooms, rawContacts, rawReads, clearedBefore] = await Promise.all([
                db('SMEMBERS', `user_rooms:${emailLower}`),
                db('SMEMBERS', `contacts:${emailLower}`),
                db('HGETALL', `room_reads:${room}`),
                db('HGET', `room_cleared:${room}`, emailLower),
            ]);
            rooms    = { result: rawRooms    ?? [] };
            contacts = { result: rawContacts ?? [] };
            reads    = parseHash(rawReads);

            // "Очистить у себя" — скрываем всё, что было отправлено до этой отметки,
            // только для нас; у остальных участников история остаётся как была.
            if (clearedBefore) {
                const cutoff = Number(clearedBefore);
                messages = (messages ?? []).filter(raw => {
                    try {
                        const m = JSON.parse(decodeURIComponent(raw));
                        return !m.ts || m.ts > cutoff;
                    } catch { return true; }
                });
            }
            }
        }

        return response.status(200).json({ messages: { result: messages ?? [] }, rooms, contacts, reads });

    } catch (err) {
        if (err.status === 401) return response.status(401).json({ status: 'error', code: err.code || 'auth', message: err.message });
        if (err.status && err.status < 500 || err.status === 502 || err.status === 503)
            return response.status(err.status).json({ status: 'error', code: err.code, message: err.message });
        console.error('[GeLink API]', err);
        return response.status(500).json({ status: 'error', message: 'Internal server error' });
    }
}
