# dating backend (Render)

Ez a csomag Render **File Upload** módban is működik (nincs benne extra gyökérmappa).
A korábbi hibád: `Cannot find module .../src/index.js` akkor történik, ha a Renderre feltöltött csomagban a `src/` mappa nem a projekt gyökerében van.

## Render beállítás (minimál)
1. Render → New → Web Service (fizetős plan)
2. Feltöltés: a ZIP tartalmát töltsd fel úgy, hogy a `package.json` **a gyökérben** legyen.
3. Build Command: `npm install`
4. Start Command: `npm start`

## Kötelező Environment változók
- DATABASE_URL  (Render Postgresból)
- JWT_SECRET
- CORS_ORIGINS  (a két Netlify domain)

Stripe-hoz:
- STRIPE_SECRET_KEY
- STRIPE_WEBHOOK_SECRET
- STRIPE_SUCCESS_URL = https://dating-2-7jsh.onrender.com/stripe/success
- STRIPE_CANCEL_URL  = https://dating-2-7jsh.onrender.com/stripe/cancel
- SITE_FORRORANDI_URL = https://forrorandi.netlify.app/#credits
- SITE_SZERELMESSZIVEK_URL = https://szerelmesszivek.netlify.app/#credits

## Price ID-k
A 6 db Price ID **be van égetve** a kódba (mindkét oldalnak ugyanaz), ezért a `STRIPE_PACKAGES`-t nem muszáj beállítanod.
Ha mégis át akarod írni, akkor Render ENV-ben felülírhatod `STRIPE_PACKAGES`-szel (JSON).

## Stripe webhook
Stripe Dashboard → Webhooks:
- Endpoint: https://dating-2-7jsh.onrender.com/v1/stripe/webhook
- Event: checkout.session.completed
