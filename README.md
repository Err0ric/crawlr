# Crawlr

OSINT investigation dashboard powered by FastAPI and Claude AI. Aggregate results from multiple reconnaissance modules through a single dark-themed web interface.

## Modules

| Module | Type | Description |
|--------|------|-------------|
| Sherlock | Free | Username enumeration across social platforms |
| Holehe | Free | Email-to-account detection |
| theHarvester | Free | Domain and subdomain recon |
| HIBP | API | Breach database lookup |
| Hunter.io | API | Domain email discovery |
| Shodan | API | Exposed service scanning |
| AI Analysis | Key | Claude-powered result interpretation |

## Setup

```bash
git clone https://github.com/Err0ric/crawlr.git
cd crawlr
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn anthropic
```

## Run

```bash
uvicorn main:app --reload
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

## API Key

The app optionally uses a Claude API key for AI-powered analysis. The key is stored in browser session memory only — never sent to or stored on the server.
