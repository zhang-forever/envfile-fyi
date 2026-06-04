# envfile.fyi

Drag in a `.env` file. Instantly see what each key is, whether it's exposed on GitHub, and generate a safe `.env.example`.

## Why
Leaked `.env` files are the #1 cause of cloud security incidents. Most developers don't know which keys are dangerous until it's too late.

## Tech
- React + Vite (pure client-side, no server)
- WASM for file parsing
- Pattern matching against known key formats (AWS, Stripe, GitHub tokens, etc.)
- GitHub API to check for public exposure (optional)

## Features (MVP)
- Drag-and-drop `.env` file parsing
- Auto-detect key types (AWS_ACCESS_KEY, STRIPE_SECRET, etc.)
- Flag potentially leaked keys (committed to public repos)
- One-click `.env.example` generation
- All processing happens in browser — your secrets never leave your machine

## Dev
```bash
npm install
npm run dev
```
