# ForensiQ frontend

The frontend is a React/Vite application with two connected surfaces:

- **Protection mode** — mailbox-oriented verdicts, plain-language reasons, safe actions, read-only email preview.
- **Investigator mode** — authentication, IOCs, intelligence, GeoIP, routing, graph, evidence, AI citations, and related cases.

The Vite development server proxies `/api` to `http://localhost:8000`.

```bash
npm install
npm run dev -- --host 0.0.0.0 --port 3000
npm run lint
npm run build
```

The interface visibly labels the synthetic Gmail provider and keeps Gmail actions read-only.
