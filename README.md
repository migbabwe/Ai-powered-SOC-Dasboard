# Ai-powered-SOC-Dasboard.
PROJECT STRUCTURE ───────────────────────────────────────────────────────
soc-dashboard/
├── backend/                        # FastAPI (deploy to Railway / Render / EC2)
│   ├── main.py                     # App entry point + CORS
│   ├── config.py                   # Pydantic settings (reads .env)
│   ├── models.py                   # Pydantic schemas
│   ├── requirements.txt
│   ├── .env                        # Never commit — see .env.example
│   ├── services/
│   │   ├── wazuh.py               # Wazuh API client + mock data
│   │   └── openai_analysis.py     # OpenAI GPT-4o mini integration
│   └── routers/
│       ├── alerts.py              # GET/POST /api/alerts
│       ├── analysis.py            # POST /api/analysis/analyze
│       ├── devices.py             # GET /api/devices
│       └── auth.py                # GET /api/auth/me
│
└── frontend/                       # Next.js 14 (deploy to Vercel)
├── app/
│   ├── layout.tsx
│   ├── page.tsx               # → renders dashboard
│   └── api/
│       ├── alerts/route.ts    # Proxies to FastAPI
│       └── sync/route.ts
├── components/
│   ├── Sidebar.tsx
│   ├── AlertTable.tsx
│   ├── AnalysisPanel.tsx
│   ├── StatCard.tsx
│   ├── SeverityBadge.tsx
│   └── DeviceGrid.tsx
├── lib/
│   ├── api.ts                 # Typed fetch wrappers
│   └── supabase.ts            # Supabase client
├── types/
│   └── alert.ts               # TypeScript interfaces
├── .env.local                 # Never commit
└── SOCDashboard.jsx           # ← The full artifact component

What was built
Interactive Dashboard (SOCDashboard.jsx)
The live artifact above is fully interactive. Try:

Overview tab — stat cards, 24h alert volume bar chart, top triggered rules, severity distribution
Alert Feed tab — click any alert row to slide open the AI analysis panel on the right; filter by CRITICAL/HIGH/MEDIUM/LOW; search by keyword
Devices tab — per-agent cards showing status, alert count, and worst-case severity


Backend — 11 files
FileRolemain.pyFastAPI app, CORS config, router mounting, lifespan hookconfig.pyPydantic-settings — all secrets from .env, never hardcodedmodels.pyPydantic schemas: RawWazuhAlert, AIAnalysis, EnrichedAlert, DashboardStats, Deviceservices/wazuh.pyWazuh JWT auth, alert fetch, auto-fallback to 6 realistic mock alerts when no credsservices/openai_analysis.pyGPT-4o mini with JSON mode, structured prompt builder, rule-based fallback if API key missingrouters/alerts.pyGET /api/alerts (paginated, filtered), GET /api/alerts/stats, POST /api/alerts/sync (background task), GET /api/alerts/{id}routers/analysis.pyPOST /api/analysis/analyze — on-demand AI triage for any alertrouters/devices.pyGET /api/devices — agent inventory derived from alert datarouters/auth.pyGET /api/auth/me — Supabase JWT validationrequirements.txtPinned deps: FastAPI, OpenAI SDK, Supabase, httpx, pydantic-settingsPROJECT_STRUCTURE.mdFull folder map, Next.js API route proxy, TypeScript API client, Supabase schema SQL, Railway + Vercel deploy config

Key architectural decisions
Mock-first, prod-ready — Wazuh and OpenAI both fall back gracefully when not configured, so you can develop and demo without live credentials.
Prompt engineering — The OpenAI prompt forces JSON mode, uses low temperature (0.2) for consistent output, and includes all relevant Wazuh fields so the model can reason about actual threat context rather than generic advice.
Next.js API proxy — The frontend never calls the FastAPI backend directly. All requests go through app/api/ routes, keeping your backend URL and any backend secrets off the client.
Supabase for persistence — The PROJECT_STRUCTURE.md includes the SQL schema with RLS policies: service role can write, authenticated users can read.

Next steps to wire it up

Copy backend files, run pip install -r requirements.txt, add .env
Run: uvicorn main:app --reload
Hit POST /api/alerts/sync to seed the cache with Wazuh (or mock) data
Connect the React component to fetchAlerts() from lib/api.ts replacing the MOCK_ALERTS constant
Deploy backend to Railway, frontend to Vercel
