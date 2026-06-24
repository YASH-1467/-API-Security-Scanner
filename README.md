# API Security Scanner

A Python tool that tests an API endpoint for common security
misconfigurations, the same checks real API security testers perform.

## Why I Built This

After building an HTTP Security Headers Analyzer for websites, I
realized most modern apps run on APIs — the invisible data layer
behind apps like Instagram or food delivery apps. I wanted to
understand how APIs can be insecure, not just websites.

## What It Checks

1. **Authentication** — does the API return real data without any login/token?
2. **Error Message Leakage** — does a broken request leak internal details
   (file paths, stack traces) that attackers could use?
3. **Common Endpoint Exposure** — are commonly-guessed paths like
   `/admin` or `/config` accidentally exposed?
4. **Rate Limiting** — does the API show any sign of limiting repeated requests?

## Ethics Note

This tool is tested only against `jsonplaceholder.typicode.com`, a
public API explicitly built for developers to practice against safely
and legally. Testing live production APIs without explicit permission
is illegal — this project is built and run entirely within legal,
intended-for-practice boundaries.

## Usage

```bash
pip install requests
python api_scanner.py
