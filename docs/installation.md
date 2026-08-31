# Installation

## Local development

Requires Python 3.11 or newer.

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# macOS/Linux
source .venv/bin/activate

python -m pip install -e .
```

The install exposes the `aps` command:

```bash
aps --help
```

The project is intended for authorized defensive network discovery only.

## Dashboard

```bash
python web/app.py
```

Open `http://127.0.0.1:5000`.

## Docker

```bash
docker compose up --build
```

Keep the dashboard on a trusted network and place authentication/TLS in front of it before exposing it to untrusted users.
