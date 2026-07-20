# slprov2 Auth Site (GitHub → Render)

GitHub Pages tek başına güvenli auth tutamaz (şifre/secret client'ta olur).
Bu klasör: **web admin panel + kırılması zor API**. GitHub'a push → Render'a bağla.

## Yerel

```bat
cd auth-server
python server.py
```

Panel: http://127.0.0.1:8787  
İlk açılışta konsolda bootstrap admin şifresi basılır (veya env ver).

```bat
set SLPROV2_ADMIN_USER=admin
set SLPROV2_ADMIN_PASSWORD=cok-guclu-sifre
python server.py
```

## GitHub → Render (önerilen)

1. Bu `auth-server` klasörünü (veya repo root'u) GitHub'a push et
2. [render.com](https://render.com) → New → Blueprint → `render.yaml` seç
3. Env:
   - `SLPROV2_ADMIN_PASSWORD` = güçlü şifre
   - `SLPROV2_MASTER_SECRET` = otomatik generate (Render)
4. Deploy sonrası URL: `https://xxx.onrender.com`
5. Loader'da **Auth URL** = o adres

## Korumalar

| Katman | Ne yapar |
|--------|----------|
| Challenge nonce | Login replay zor |
| PBKDF2 310k | Brute-force yavaş |
| Timing-safe + dummy hash | User enumeration zor |
| IP/user lockout | Brute-force kilidi |
| HWID bind | Hesap çalınsa başka PC'de olmaz |
| Kısa JWT + heartbeat | Token leak süresi kısa |
| Generic error | "invalid credentials" hep aynı |
| Admin HttpOnly cookie + CSRF | Panel XSS/CSRF'e direnç |
| Security headers | Clickjack / MIME sniff |
| Opsiyonel request HMAC | `SLPROV2_REQUIRE_SIGN=1` + loader app_secret |

## Loader

`slprov2-loader.exe` → Auth URL'ye site adresini yaz → Login → Inject.

## CLI (opsiyonel)

```bat
python admin_cli.py create --username oyuncu1 --password sifre --days 30
python admin_cli.py list
```
