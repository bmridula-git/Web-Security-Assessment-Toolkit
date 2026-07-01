# Web Security Assessment Toolkit

A single-page PHP tool that runs a lightweight security assessment against a 
given URL — inspecting HTTP response headers, common misconfigurations, and 
DNSBL/Spamhaus reputation — and lets you export the results as CSV.

## Features

- **Security header analysis** — checks for HSTS, Content-Security-Policy, 
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, 
  and server banner disclosure.
- **Common misconfiguration checks** — probes for exposed upload directories, 
  sensitive paths (`/config`, `/backup`, `/.git`, `/admin`), and login pages.
- **Cookie flag validation** — flags missing `HttpOnly`, `Secure`, and 
  `SameSite` attributes on session cookies.
- **DNSBL / Spamhaus lookup** — resolves the target's IP and checks it against 
  major blocklists (Spamhaus, SpamCop, SORBS, Barracuda).
- **CSV export** — download the full report for offline record-keeping.

## Tech stack

PHP, HTML, CSS — no external dependencies or database required.

## Running locally

```bash
php -S localhost:8000
```

Then open `http://localhost:8000/toolkit.php` and enter a domain or URL 
(e.g. `example.com`) to run an assessment.

## Notes

- This is a demonstration/portfolio project built to explore HTTP security 
  header analysis and basic web recon techniques.
- All testing during development was performed against a domain I own — 
  this tool is not intended for scanning targets you don't own or don't 
  have explicit permission to test.
- SSL certificate verification is disabled when fetching target headers, to 
  allow analysis of sites with self-signed or misconfigured certs — this is 
  fine for a local demo tool but shouldn't be replicated in production code.

