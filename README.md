# Phone Number Verifyer

A web application that allows users to upload CSV files containing phone numbers, process them using the NumLookup API, and download enriched contact data.

## Features

* User registration and login
* Secure API key storage for NumLookup API
* CSV upload support
* Column selection for phone number field
* Phone number enrichment using NumLookup API
* Download processed CSV output

## Installation

```bash
git clone <your-repo-url>
cd phone-validator
npm install
cp .env.local.example .env.local
# Edit .env.local with your secrets
npm run dev
```

## Environment Variables

Copy `.env.local.example` to `.env.local`:

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Yes | Signs login tokens (long random string) |
| `USERDATA_ENC_KEY` | Yes | Encrypts stored Numlookup API keys (keep stable across deploys) |
| `DATABASE_URL` | **Yes on Vercel** | Postgres connection string for persistent user accounts |
| `PORT` | No | Local dev port (default 3000) |

### Vercel deployment (important)

On Vercel, the app runs as serverless functions. **Without `DATABASE_URL`, user accounts are written to `/tmp`, which is wiped on cold starts and not shared between instances** — users will appear to lose their account and API key.

1. In the Vercel project, add **Postgres** (Vercel Postgres / Neon) or any hosted Postgres.
2. Copy the connection string into the `DATABASE_URL` environment variable.
3. Set the same `JWT_SECRET` and `USERDATA_ENC_KEY` on every deploy (do not rotate `USERDATA_ENC_KEY` casually).
4. Redeploy.

The app creates the `users` table automatically on first use.

## User Flow

1. User registers or logs in
2. User enters their NumLookup API key
3. User uploads a CSV file
4. User selects the column containing phone numbers
5. System processes each phone number through NumLookup API
6. User downloads enriched CSV file

## Security Notes

* Never expose API keys publicly
* User API keys are encrypted at rest with `USERDATA_ENC_KEY`
* Validate uploaded CSV files
