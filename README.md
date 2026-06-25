# CyberSuite

CyberSuite is a Flask-based cybersecurity toolkit with authentication, file crypto, phishing checks, and scan dashboards.

## Local setup

1. Create a virtual environment and install dependencies:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
2. Copy `.env.example` to `.env` and fill in the required values.
3. Start the app:
   ```powershell
   python run.py
   ```

## Vercel setup

1. Push this project to GitHub.
2. Import the repository in Vercel.
3. In Vercel project settings, add these environment variables:
   - `SECRET_KEY`
   - `DATABASE_URL`
   - `VIRUSTOTAL_API_KEY`
   - `ABUSEIPDB_API_KEY`
   - `URLSCAN_API_KEY`
   - `GOOGLE_SAFE_BROWSING_API_KEY`
   - `ISMALICIOUS_API_KEY`
   - `ISMALICIOUS_API_URL`
4. Deploy the project. Vercel will use `vercel.json` and `api/index.py`.

## Production notes

- Use a persistent PostgreSQL database in `DATABASE_URL` for production.
- If `DATABASE_URL` is empty, the app uses SQLite in `/tmp` on Vercel, which is not persistent.
- File uploads and generated exports are stored in `/tmp` on Vercel, so they are temporary.
- Port scanning based on `nmap` may not work in Vercel serverless runtime.

## Example `DATABASE_URL`

```text
postgresql://username:password@host:5432/database_name
```
