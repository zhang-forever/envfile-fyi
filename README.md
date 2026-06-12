# envfile.fyi

[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-6-646CFF?logo=vite&logoColor=white)](https://vitejs.dev)
[![License](https://img.shields.io/badge/license-MIT-purple)](./LICENSE)

🔐 **Drag in a `.env` file. Instantly see what each key is, whether it's exposed on GitHub, and generate a safe `.env.example`.**

## 🎯 Why

Leaked `.env` files are the #1 cause of cloud security incidents. Most developers don't know which keys are dangerous until it's too late. `envfile.fyi` helps you identify and audit your environment variables before they become a liability.

## ✨ Features

- **Drag-and-drop parsing** — Drop any `.env` file, get instant analysis
- **Key type detection** — Auto-identifies AWS, Stripe, GitHub, database credentials, and 50+ other formats
- **Leak detection** — Checks if keys are exposed in public GitHub repos
- **Safe example generator** — One-click `.env.example` with values redacted
- **100% client-side** — All processing happens in your browser. Secrets never leave your machine.
- **No server required** — Pure client-side, zero network requests for core functionality

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Start dev server
npm run dev

# Open http://localhost:5173
```

## 🛠️ Tech Stack

- **Frontend:** React 19 + Vite 6
- **Parsing:** WebAssembly for fast `.env` parsing
- **Security:** Pattern matching against known key formats
- **Privacy:** Zero network requests (optional GitHub API for leak checking)

## 🔍 Supported Key Formats

| Category | Examples |
|----------|----------|
| **Cloud** | `AWS_ACCESS_KEY`, `AZURE_CLIENT_SECRET`, `GCP_SERVICE_ACCOUNT` |
| **Payment** | `STRIPE_SECRET_KEY`, `PAYPAL_CLIENT_SECRET` |
| **Social** | `GITHUB_TOKEN`, `TWITTER_API_KEY`, `DISCORD_BOT_TOKEN` |
| **Database** | `DATABASE_URL`, `REDIS_URL`, `MONGODB_URI` |
| **Email** | `SENDGRID_API_KEY`, `MAILGUN_API_KEY` |
| **And 50+ more...** | Pattern-based detection for any key format |

## 📦 Build

```bash
npm run build
# Output in dist/
```

## 🔒 Security & Privacy

- **No data leaves your browser** — Core analysis is 100% client-side
- **Optional GitHub check** — Can verify if keys are exposed in public repos (requires GitHub token)
- **No telemetry** — Zero analytics, zero tracking
- **Open source** — Audit the code yourself

## 📄 License

MIT
