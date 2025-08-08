AWS Topology Enumerator – single‑file web app

What it does
------------
Lets you enumerate AWS resources using your own credentials (env, shared profile, or paste into the UI).
Works with **limited privileges** – anything that returns AccessDenied is skipped and reported as a warning.
Builds an **interactive graph** of resources and **network connections** (security-group flows, routes, LB listeners/targets, etc.).
Different colors: resource edges vs network/protocol edges. Click nodes/edges to see full AWS details.
Cross‑platform (Windows/Linux/Mac). One Python file. No DB. No telemetry.
**Built‑in tests**: visit `/_selftest` for quick checks; `/_health` for a health probe.

Run it
------
1) Python 3.10+ recommended

   python -m venv .venv
   . .venv/bin/activate   # Windows: .venv\\Scripts\\activate
   pip install fastapi uvicorn boto3 jinja2

2) Start (local only):

   python app.py

   # or
   uvicorn app:app --host 127.0.0.1 --port 8000

3) Open http://127.0.0.1:8000 in your browser.

Security notes
--------------
• This is a local tool. It does NOT store your keys; they live in process memory only.
• Prefer environment/shared profile credentials. Pasting keys is for lab use.
• Graph shows *configuration* connections, not live flow logs.

Extend it
---------
• See SERVICE_TOGGLES and the enumerate_* functions – add more AWS services as needed.
• The bottleneck is AWS API I/O. We parallelise regions/services where safe. Tune WORKERS.
