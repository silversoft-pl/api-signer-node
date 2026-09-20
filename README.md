# @silversoft/api-signer (Node)

Podpisywanie i weryfikacja żądań HTTP zgodnie z **[RFC 9421 — HTTP Message Signatures][rfc9421]**,
bez zależności — wystarcza `node:crypto`.

```
npm install @silversoft/api-signer
```

[![RFC 9421](https://img.shields.io/badge/RFC-9421-blue)][rfc9421]
[![Node](https://img.shields.io/badge/Node-%3E%3D18-5fa04e)](package.json)

Odpowiednik dla PHP: **[silversoft/api-signer][php-repo]**. Obie paczki realizują jeden format
drutowy i są trzymane na tych samych wektorach testowych — patrz
[Zgodność ze standardem](#zgodność-ze-standardem).

> Ta paczka **podpisuje i weryfikuje**, ale niczego nie wysyła. Do wywoływania wewnętrznego API
> służy **[@silversoft/api-client][client-repo]**, który używa tej paczki pod spodem.

---

## Po co to jest

Wspólny sekret w nagłówku — `Authorization: Bearer …`, `X-Api-Key: …` albo cokolwiek w tym kształcie
— leci w całości przy każdym wywołaniu. Osiada w logach dostępu, w logach proxy, w systemach
błędów, w historii powłoki, na zrzucie ekranu w zgłoszeniu. Kto zobaczy go raz, może podszywać się
pod klienta bez ograniczeń, a sam sekret nie jest w żaden sposób związany z żądaniem, z którym
przyszedł.

Podpis rozwiązuje oba problemy. Sekret nie opuszcza żadnej ze stron: klient dowodzi jego posiadania
podpisując, serwer dowodzi tego samego przeliczając. Podpis obejmuje metodę, ścieżkę, query i skrót
ciała, więc przechwyconego żądania nie da się zmienić, przekierować na inny endpoint ani powtórzyć
po wygaśnięciu.

**Do czego:** integracje serwer–serwer, gdzie obie strony są Twoje albo partnera — API wewnętrzne,
webhooki, komunikacja między usługami bez mTLS, wszystko tam, gdzie dziś krąży klucz API.

**Do czego nie:** uwierzytelnianie użytkowników w przeglądarce. Klient potrzebuje materiału klucza,
a przeglądarka nie ma go gdzie bezpiecznie trzymać.

## Szybki start

Działa i ESM, i CommonJS:

```js
import { Credential, prepare } from '@silversoft/api-signer';
const { Credential, prepare } = require('@silversoft/api-signer');
```

### Klient

```js
import { Credential, prepare } from '@silversoft/api-signer';

const credential = new Credential('moja-usluga', process.env.API_SECRET);

const signed = prepare(credential, 'POST', 'https://api.example.com/v1/users/update', {
    user: { id: 1, email: 'jan@example.com' },
});

await fetch(signed.url, signed.toFetchOptions());
```

`signed.body` to ładunek w postaci podpisanej. Nie serializuj go drugi raz — oddanie obiektu
z powrotem klientowi HTTP, żeby zakodował go ponownie, to najczęstsza przyczyna błędu
`signature does not match`.

### Serwer

```js
import { Credential, Policy, Request, keyIdOf, verify } from '@silversoft/api-signer';

const url = new URL(req.url, `https://${req.headers.host}`);
const request = new Request(req.method, url.pathname, url.search, rawBody, req.headers);

const keyId = keyIdOf(request);                 // którego klucza szukać
const entry = keys[keyId];                      // nigdy w repozytorium

if (!entry) {
    res.writeHead(401).end('Unauthorized');
    return;
}

const result = verify(request, Credential.fromConfig(keyId, entry), new Policy());

if (result.failed) {
    console.warn('api auth odrzucone:', result.reason);   // szczegół idzie do logu
    res.writeHead(401).end('Unauthorized');               // i nigdy do klienta
    return;
}
```

`rawBody` to muszą być dokładnie odebrane bajty. Odczytaj je, **zanim** zadziała jakikolwiek parser
ciała, i przekaż ten sam bufor do weryfikacji i do `JSON.parse`.

## Model bezpieczeństwa

### Co podpis chroni

| | |
|---|---|
| **Autentyczność** | żądanie przyszło od kogoś, kto ma klucz dla `keyid` |
| **Integralność** | metoda, ścieżka, query i ciało są dokładnie tym, co podpisano |
| **Świeżość** | podpis jest ważny tylko między `created` a `expires` |

### Czego nie chroni

- **Poufności.** Żądanie jest podpisane, nie zaszyfrowane. **TLS jest nadal obowiązkowy.**
- **Powtórzenia w oknie ważności**, chyba że skonfigurujesz magazyn nonce (niżej). Okno jest takie,
  jakie ustawisz; domyślnie 300 sekund.
- **Przejętego klucza.** Przy `hmac-sha256` serwer trzyma ten sam sekret, którym podpisuje klient,
  więc włamanie po którejkolwiek stronie kompromituje tę parę. Użyj `ed25519` tam, gdzie serwer
  ma trzymać wyłącznie klucz publiczny.

### Założenia, na których ta paczka stoi

Nie są opcjonalne. Ich złamanie po cichu odbiera większość korzyści:

1. **TLS przy każdym wywołaniu.** Podpis nie zastępuje szyfrowania.
2. **Jeden klucz na parę usług.** Klucz wspólny dla trzech usług pozwala każdej podszyć się
   pod pozostałe.
3. **Jeden klucz na środowisko.** Wspólny sekret staging i produkcji oznacza, że żądanie
   przechwycone na staging da się powtórzyć na produkcji. Paczka świadomie nie ma zabezpieczenia
   opartego na `tag`, bo skopiowana konfiguracja kopiuje też jego wartość — rozdzielne klucze
   są właściwym rozwiązaniem.
4. **Co najmniej 32 bajty entropii na sekret.** `crypto.randomBytes(48).toString('base64')`.
5. **Klucze nigdy w systemie kontroli wersji.** Ignoruj plik, dostarcz `.sample` albo czytaj
   ze zmiennych środowiskowych.

## Polityka weryfikacji

**Sam poprawny podpis nic nie znaczy.** Klient może legalnie podpisać żądanie obejmujące wyłącznie
`@method`; podpis się zweryfikuje, a te same bajty zadziałają wobec dowolnej ścieżki z dowolną
treścią. RFC 9421 na to pozwala, więc każdy weryfikator musi narzucić własne minimum.

`Policy` jest tym minimum i działa domyślnie:

```js
const policy = new Policy({
    requiredComponents: ['@method', '@path', '@query', 'content-digest'],
    requiredParams: ['keyid', 'created', 'expires', 'alg'],
    allowedAlgorithms: ['hmac-sha256'],
    maxLifetime: 300,   // sekundy; klient nie wystawi sobie podpisu na rok
    clockSkew: 30,      // sekundy
    requiredTag: null,  // ustaw tylko, jeśli używasz tagów
    nonceStore: null,   // patrz niżej
});
```

Wymagania można dokładać; zdejmowanie ich w działającym systemie nie ma sensu — `Policy.none()` istnieje wyłącznie
do odtwarzania opublikowanych wektorów testowych i nie wolno go użyć na działającym endpointcie.

Niezależnie od polityki weryfikator zawsze przelicza `Content-Digest` z rzeczywistego ciała. Bez
tego podpis obejmowałby jedynie *deklarację* nadawcy o ciele.

### Ochrona przed powtórzeniem

`nonce` jest zawsze wysyłany. Jego sprawdzanie jest opcjonalne, bo kosztuje zapis przy każdym
żądaniu, a przy więcej niż jednej instancji — wspólny magazyn. Lokalny cache daje złudzenie
ochrony, podczas gdy instancje nie widzą swoich nonce.

```js
policy.nonceStore = (keyId, nonce, ttl) => cache.add(`api-nonce:${keyId}:${nonce}`, 1, ttl);
```

Zwróć `false`, gdy nonce już był. Wywołanie jest z założenia synchroniczne, więc oprzyj je o coś,
co da się odczytać bez `await` — LRU w procesie przed Redisem albo klienta synchronicznego.

Przy operacjach niedempotentnych pewniejszą ochroną jest idempotentność na poziomie aplikacji
(naturalny klucz, upsert, status operacji); nonce zatrzymuje wyłącznie *to samo* żądanie wysłane
dwa razy.

## Referencja API

### `Credential`

| | |
|---|---|
| `new Credential(keyId, key, alg = 'hmac-sha256', auth = 'signed')` | `key` to Buffer albo string z surowym materiałem klucza |
| `Credential.fromConfig(keyId, entry)` | z obiektu konfiguracyjnego: `key` albo `key_base64`, plus `alg`, `auth`. Wartość skalarna oznacza klucz w starym schemacie |
| `credential.isLegacy()` | `true`, gdy poświadczenie jest ustawione na schemat sprzed podpisów |
| `credential.legacyHeader()` | `base64("<keyId>|<klucz>")`, na potrzeby migracji |

Algorytmy: `hmac-sha256` (klucz = wspólny sekret) i `ed25519` (klucz = 32-bajtowe ziarno,
64-bajtowy klucz prywatny albo PEM przy podpisywaniu; 32-bajtowy klucz publiczny albo PEM przy
weryfikacji). `algorithm.ed25519PublicKeyFrom(privateKey)` wyprowadza klucz publiczny
do przekazania weryfikatorom.

### `Request`

| | |
|---|---|
| `new Request(method, path, query, body, headers, authority, scheme)` | nazwy nagłówków są sprowadzane do małych liter |
| `Request.fromUrl(method, url, body, headers)` | rozkłada ścieżkę, query, host i schemat za Ciebie |

### `prepare(...)` → `SignedRequest`

Zwraca `.method`, `.url`, `.body` (dokładnie podpisane bajty) i `.headers`.
`.toFetchOptions(init)` domiesza podpisane nagłówki do obiektu opcji dla `fetch`/`undici`;
`.headerLines()` daje linie `Nazwa: wartość`.

Opcje: `components`, `label`, `created`, `expires`, `nonce`, `tag`, `lifetime`, `headers`.

### `sign` / `verify`

`sign(credential, request, params = null)` zwraca nagłówki do dodania. **Podane `params` są używane
dosłownie** — nic nie jest dopisywane za plecami wołającego, dzięki czemu opublikowane wektory
testowe odtwarzają się co do bajta. `null` daje wartości domyślne.
`signatureBaseOf(request, params)` wystawia bazę podpisu do diagnostyki.

`keyIdOf(request)` zwraca `keyid` deklarowany przez żądanie, z obu schematów, żeby dało się znaleźć
poświadczenie przed weryfikacją. Wartość jest z definicji nieuwierzytelniona: wybiera klucz
do sprawdzenia, niczego nie przyznaje.

`verify(request, credential, policy = null)` zwraca `Result` z polami `failed`, `reason`, `label`,
`params` i `components`. **`reason` jest do logu, nigdy do odpowiedzi** — pokazanie wołającemu
różnicy między „nieznany klucz” a „zły podpis” daje mu narzędzie do zgadywania.

## Duże ładunki

Ciało jest objęte przez `Content-Digest` (RFC 9530), więc da się je haszować przyrostowo przez
`digest.ofStream(readable)`, gdy to Ty je produkujesz. Do weryfikacji przekaż `verify()` odebrane
bajty.

- Haszowanie idzie rzędu 1–2 GB/s; ciało 100 MB to około 0,1 s procesora.
- Sufitem pamięci jest obsługa ciała, nie podpis: zbuforowanie żądania i `JSON.parse` trzyma ładunek
  dwa razy — niezależnie od tej paczki.

**`multipart/form-data` nie jest wspierane na podpisanych endpointach**, symetrycznie do paczki PHP,
gdzie środowisko konsumuje takie ciało, zanim kod aplikacji zdąży je zahaszować. Duże pliki wysyłaj
jako surowe ciało (`application/octet-stream`) albo base64 w JSON-ie, a `multipart/form-data`
odrzucaj kodem 415.

## Diagnostyka

Każde odrzucenie zwraca wołającemu to samo — celowo — więc zaczynaj od `result.reason` w logu
serwera.

| Powód | Prawdopodobna przyczyna | Jak sprawdzić |
|---|---|---|
| `signature does not match` | ciało zserializowane dwa razy — klient zakodował JSON, a klient HTTP zakodował go ponownie | zaloguj `signed.body` po stronie klienta i surowe ciało po stronie serwera; muszą być identyczne co do bajta |
| `signature does not match` | proxy przepisało ścieżkę | porównaj `@path`/`@query` z `signatureBaseOf()` z `req.url` serwera |
| `signature does not match` | parametr podpisu zmieniony w locie | porównaj odebrany `Signature-Input` z tym, który wysłał klient |
| `Content-Digest does not match the body` | parser ciała podmienił surowe bajty przed weryfikacją | przechwyć `rawBody`, zanim dotknie go jakikolwiek middleware |
| `signature has expired` / `created is in the future` | zegary różnią się o więcej niż `clockSkew` | `timedatectl status` na obu hostach; NTP jest wymogiem twardym |
| `signature lifetime exceeds the allowed maximum` | klient ustawił `expires` zbyt daleko | dopasuj `lifetime` klienta do `maxLifetime` serwera |
| `component "…" is not covered` | klient podpisał mniej komponentów, niż wymaga serwer | porównaj `components` klienta z `policy.requiredComponents` |
| `algorithm does not match the credential` | `alg` w nagłówku różni się od skonfigurowanego | sprawdź `alg` we wpisie klucza po stronie serwera |
| `credential is configured for the legacy scheme` | wpis klucza nadal ma `auth: 'legacy'` | przestaw na `'signed'`, gdy klient już przeszedł |
| `missing Signature-Input or Signature header` | proxy usunęło nieznane nagłówki albo klient jest wciąż na starym schemacie | zrzuć surowe nagłówki żądania na serwerze |

## Zgodność ze standardem

Zaimplementowane: podpisywanie i weryfikacja żądań; komponenty pochodne `@method`, `@target-uri`,
`@authority`, `@scheme`, `@request-target`, `@path`, `@query`, `@query-param`; parametry podpisu
`created`, `expires`, `keyid`, `alg`, `nonce`, `tag`; wiele podpisów na żądanie; `hmac-sha256`
i `ed25519`; `Content-Digest` z SHA-256 i SHA-512 ([RFC 9530][rfc9530]).

Niezaimplementowane: podpisywanie odpowiedzi i `@status`; algorytmy RSA i ECDSA; parametry
komponentów spoza `name` (`sf`, `key`, `bs`, `req`, `tr`).

Jak zgodność jest wykazywana:

1. **Opublikowane wektory z RFC 9421, Appendix B**, których nie wyprodukowała żadna z naszych
   implementacji, są odtwarzane co do bajta — bazy podpisu B.2.1–B.2.3 oraz pełne podpisanie
   i weryfikacja B.2.5 (`hmac-sha256`) i B.2.6 (`ed25519`).
2. **Test krzyżowy** uruchamia tę paczkę i paczkę PHP obok siebie: każda podpisuje, druga
   weryfikuje, a obie muszą wypuścić identyczne bajty. Wektory statyczne dowodzą tylko tego, że
   implementacja nadal zgadza się z nagraniem; to dowodzi, że obie zgadzają się ze sobą. Test
   mieszka tutaj, w `tools/cross/run.js`, i uruchamia się w CI **obu** repozytoriów, także
   cyklicznie, bo zmiana w jednym repozytorium jest dla drugiego niewidoczna.
3. **Kontrola interop** z niezależną implementacją RFC 9421
   (`@misskey-dev/node-http-message-signatures`) potwierdza, że wyprowadza ona tę samą bazę podpisu
   z naszych podpisanych żądań.

   Ta kontrola wykryła jedną rozbieżność, odnotowaną zamiast zamiecionej: dla żądania bez query
   stringu [RFC 9421 §2.2.7][rfc9421-query] określa wartość komponentu `@query` jako „samo wiodące
   `?`”, czyli linię `"@query": ?`. Tamta biblioteka emituje wartość pustą. **My trzymamy się
   specyfikacji**, a `tools/interop/run.mjs` zgłasza błąd, gdyby rozbieżność przestała występować —
   wyjątek nie przeżyje poprawki po ich stronie.

### Wektory testowe

`vectors/` to kopia; **właścicielem jest repozytorium PHP**, bo generator jest w PHP. Odświeżenie:

```bash
npm run sync-vectors     # kopiuje z ../api-signer-php albo z $API_SIGNER_PHP
```

Zacommituj wynik. Test krzyżowy nie przechodzi, gdy kopie się różnią, więc nie rozjadą się po cichu.

## Wersjonowanie i zgodność

Semantyczne wersjonowanie, trzymane równo z paczką PHP: obie mają ten sam major i minor dla tego
samego formatu drutowego. **Każda zmiana sposobu wyprowadzania bazy podpisu jest zmianą łamiącą**
i trafi wyłącznie do wydania głównego, bo po cichu unieważnia podpisy u wszystkich klientów. Dodanie
algorytmu albo funkcji pomocniczej to wydanie minor.

Wspierane i testowane w CI: Node 18, 20, 22, 24.

## Migracja ze zwykłego klucza API

Poświadczenie niesie tryb `auth`, więc oba schematy dzielą jedno miejsce wywołania:

```js
{ auth: 'legacy' }   // Api-Authorization: base64("<keyId>|<klucz>")
{ auth: 'signed' }   // RFC 9421
```

`prepare()` zwraca ten sam obiekt w obu trybach, więc kod klienta pisze się raz, a przełącznik
siedzi w konfiguracji. Po stronie serwera odrzucaj stary nagłówek od klienta już oznaczonego jako
`signed` — inaczej wykradziony stary klucz działa dalej mimo migracji.

## Rozwój

```bash
node --test test/
node tools/interop/run.mjs      # wymaga: npm install --no-save @misskey-dev/node-http-message-signatures
```

Test krzyżowy wymaga też paczki PHP:

```bash
git clone https://github.com/silversoft-pl/api-signer-php ../api-signer-php
cd ../api-signer-php && composer install && cd -
node tools/cross/run.js         # albo: API_SIGNER_PHP=/sciezka/do/repo-php node tools/cross/run.js
```

Nowy przypadek brzegowy trafia do `vectors/testvectors.json` — dodaj go w repozytorium PHP,
zregeneruj tam, potem `npm run sync-vectors` tutaj i zacommituj oba, żeby obie implementacje były
nim związane.

## Licencja

MIT — patrz [LICENSE](LICENSE).

[rfc9421]: https://www.rfc-editor.org/rfc/rfc9421.html
[rfc9421-query]: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.7
[rfc9530]: https://www.rfc-editor.org/rfc/rfc9530.html
[php-repo]: https://github.com/silversoft-pl/api-signer-php
[client-repo]: https://github.com/silversoft-pl/api-client-node
