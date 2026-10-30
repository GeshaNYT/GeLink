# Вход через GeLink (OAuth 2.0)

GeLink умеет работать как провайдер входа: сторонний сайт (например, Minva Messenger)
показывает кнопку «Войти через GeLink», а GeLink подтверждает личность пользователя
и отдаёт его профиль. Пароль и переписка никогда не передаются.

## 1. Настройка на стороне GeLink (Vercel)

Добавьте переменную окружения `OAUTH_CLIENTS` (Vercel → Settings → Environment Variables):

```json
{
  "minva": {
    "name": "Minva Messenger",
    "secret": "ДЛИННАЯ_СЛУЧАЙНАЯ_СТРОКА",
    "redirect_uris": ["https://ДОМЕН-MINVA/auth/gelink/callback"]
  }
}
```

- `secret` — сгенерируйте, например, `openssl rand -hex 32`, и передайте другу лично (не в чат/репозиторий).
- `redirect_uris` — точные адреса, куда можно возвращать пользователя. Сравнение строгое.

После изменения переменной сделайте Redeploy.

## 2. Адреса (замените `https://GELINK` на ваш домен)

| Что | Метод | Адрес |
|---|---|---|
| Страница входа | GET (в браузере) | `https://GELINK/oauth/authorize` |
| Обмен code → токен | POST (с сервера) | `https://GELINK/api/index?action=oauthToken` |
| Профиль | GET (с сервера) | `https://GELINK/api/index?action=oauthUserinfo` |

## 3. Что сделать на стороне Minva

### Шаг 1. Кнопка «Войти через GeLink»
Сервер Minva генерирует `state` и PKCE `code_verifier`, сохраняет их в сессии
и перенаправляет пользователя на:

```
https://GELINK/oauth/authorize
  ?response_type=code
  &client_id=minva
  &redirect_uri=https://ДОМЕН-MINVA/auth/gelink/callback
  &scope=profile email
  &state=СЛУЧАЙНАЯ_СТРОКА
  &code_challenge=BASE64URL(SHA256(code_verifier))
  &code_challenge_method=S256
```

### Шаг 2. Колбэк
GeLink вернёт пользователя на `redirect_uri?code=...&state=...`
(или `?error=access_denied&state=...`, если он нажал «Отмена»).
Проверьте, что `state` совпадает с сохранённым.

### Шаг 3. Обмен code на токен (только с сервера!)
```
POST https://GELINK/api/index?action=oauthToken
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "code": "...",
  "redirect_uri": "https://ДОМЕН-MINVA/auth/gelink/callback",
  "client_id": "minva",
  "client_secret": "...",
  "code_verifier": "..."
}
```
Ответ: `{ "access_token": "...", "token_type": "Bearer", "expires_in": 3600, "scope": "profile email" }`.
Код одноразовый и живёт 60 секунд.

### Шаг 4. Профиль
```
GET https://GELINK/api/index?action=oauthUserinfo
Authorization: Bearer ACCESS_TOKEN
```
Ответ:
```json
{
  "sub": "491591a6-...",          // постоянный ID в GeLink — по нему привязывать аккаунт
  "name": "Гена",
  "preferred_username": "gena",
  "picture": "data:image/...",    // или null; может быть data-URL
  "bio": "",
  "email": "a@x.com"              // только если запрошен scope email
}
```

### Шаг 5. Аккаунт в Minva
- Добавьте в таблицу пользователей поле `gelink_id` (уникальное).
- Есть пользователь с `gelink_id = sub` → войти в него.
- Нет → создать новый аккаунт, заполнив имя, ник, аватар из ответа.
- **Не склеивайте аккаунты по email автоматически.** Если email совпал с существующим аккаунтом,
  попросите ввести пароль от Minva и только тогда запишите `gelink_id`.

## Пример на Node.js (Express) для Minva

```js
import crypto from 'node:crypto';

const GELINK = 'https://GELINK';
const CLIENT_ID = 'minva';
const CLIENT_SECRET = process.env.GELINK_CLIENT_SECRET;
const REDIRECT_URI = 'https://ДОМЕН-MINVA/auth/gelink/callback';

app.get('/auth/gelink', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  req.session.gelink = { state, verifier };
  const url = new URL(GELINK + '/oauth/authorize');
  url.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    scope: 'profile email', state, code_challenge: challenge, code_challenge_method: 'S256',
  });
  res.redirect(url.toString());
});

app.get('/auth/gelink/callback', async (req, res) => {
  const saved = req.session.gelink; delete req.session.gelink;
  if (req.query.error) return res.redirect('/login');
  if (!saved || req.query.state !== saved.state) return res.status(400).send('Bad state');

  const tokenRes = await fetch(GELINK + '/api/index?action=oauthToken', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code', code: req.query.code, redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code_verifier: saved.verifier,
    }),
  });
  const token = await tokenRes.json();
  if (!token.access_token) return res.status(400).send('Login failed');

  const me = await (await fetch(GELINK + '/api/index?action=oauthUserinfo', {
    headers: { Authorization: 'Bearer ' + token.access_token },
  })).json();

  let user = await db.users.findOne({ gelink_id: me.sub });
  if (!user) user = await db.users.create({
    gelink_id: me.sub, name: me.name, username: me.preferred_username, avatar: me.picture,
  });
  req.session.userId = user.id;
  res.redirect('/');
});
```
