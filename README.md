# KRYPTO LENS

KRYPTO LENS is a security-awareness demo that checks URLs, phishing messages, emails, QR-code content, and password strength. It combines a Python heuristic analysis engine with an Express.js API and a browser-based dashboard.

> **Important:** This is an educational/demo tool, not a replacement for professional threat-intelligence or antivirus products. Heuristic results can produce false positives and false negatives. Do not use it as the sole basis for security decisions.

## Repository structure

```text
KRYPTO-LENS/
├── KRYPTO_LENS.ipynb          # Original Google Colab/Jupyter Notebook
├── README.md                  # Project overview and setup instructions
├── .gitignore                 # Excludes local secrets, dependencies and runtime data
├── .env.example               # Optional API-key configuration template
└── cybershield/
    ├── analyzer.py            # Python heuristic analysis engine
    ├── server.js              # Express API and static-file server
    ├── package.json           # Node.js dependencies and start script
    ├── public/
    │   └── index.html         # KRYPTO LENS web interface
    └── data/
        └── .gitkeep           # Keeps the runtime-data directory in Git
```

## Features

- URL risk analysis using heuristic checks
- Phishing-message and email-content analysis
- Password-strength estimation
- QR-code content analysis
- Express API with rate limiting and security headers
- Dashboard statistics and local JSON persistence
- Optional Google Safe Browsing and VirusTotal URL reputation checks
- Browser-based interface with QR, language and voice-related tools

## Requirements

- Node.js 18 or later
- npm
- Python 3
- A modern browser

## Run locally (Windows PowerShell)

1. Clone or download this repository.
2. Open PowerShell in the repository folder.
3. Install the Node.js dependencies:

   ```powershell
   cd cybershield
   npm install
   ```

4. Start the application:

   ```powershell
   npm start
   ```

5. Open `http://localhost:3000` in your browser.

The server invokes `python3` to run `analyzer.py`. If your Windows installation does not recognise `python3`, update the Python executable command in `cybershield/server.js` to `python` (or configure a `python3` command in PATH).

## Optional API keys

The application works with local heuristic checks without API keys. To enable external URL reputation checks, set these environment variables before starting the server:

- `GSB_KEY` — Google Safe Browsing API key
- `VT_KEY` — VirusTotal API key

You can use `.env.example` as a reference, but **never commit real API keys or secrets**. The current server reads environment variables directly; it does not automatically load a `.env` file.

## Run the notebook

Open `KRYPTO_LENS.ipynb` in Google Colab or Jupyter. The notebook contains the original project-generation, installation, testing and Colab launch workflow. Its web-app preview cells use Google Colab-specific features, so those preview cells are intended for Colab rather than a local Jupyter session.

## Data and privacy

Runtime scan history is written to `cybershield/data/cybershield-data.json` by the server. This generated file is intentionally excluded from Git because it may contain submitted scan content. The directory is retained using `.gitkeep`.

## License

This project is distributed under the MIT License. See the [LICENSE](LICENSE) file for the complete terms. Copyright (c) 2026 Monika V.
