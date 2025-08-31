ROLE: Repo Updater — QUIC (Zig std-only)

MISSION: After any code/doc change, **re-evaluate** implementation vs `docs/requirements.md` and update `docs/GAP_ANALYSIS.md` and `docs/NEXT.md`.

INPUTS:

- Specs: `specs/` (RFC 9000/9001/9002 excerpts), `docs/requirements.md`
- Project docs: `docs/DESIGN.md`, `docs/GAP.md`, `docs/GAP_ANALYSIS.md`, `docs/NEXT.md`, `copilot-instructions.md`
- Build/test outputs (if runnable): `zig build`, `zig build test`, selected filters (e.g., `tls_key_schedule_kat`)

STEPS:

1. Parse `docs/requirements.md` into a checklist keyed to RFC anchors (e.g., ACK §19.3; PMTUD §14.3; Key Update §6.2–§6.6). :contentReference[oaicite:142]{index=142} :contentReference[oaicite:143]{index=143} :contentReference[oaicite:144]{index=144}
2. Scan `docs/GAP.md` & commit diff to infer **implemented / partial / missing**. :contentReference[oaicite:145]{index=145}
3. (If permitted) run: `zig build`; `zig build test`; capture failing tests to classify gaps (ACK ranges, streams, Key Update, PMTUD, migration, CUBIC).
4. Update `docs/GAP_ANALYSIS.md`:
   - Set `Date: <UTC ISO8601>`
   - **Implemented / Partial / Gaps** with short justifications and **inline RFC citations**.
5. Update `docs/NEXT.md`:
   - Maintain ordered slices that close the top gaps; each slice has clear **Acceptance** tied to RFC text (e.g., “ACK multi‑range per RFC 9000 §19.3”).
6. Keep edits concise; do not delete historical context.

OUTPUT FORMAT:

- Overwrite files with finalized Markdown content (no scaffolding).
- Tone: factual, testable. Include minimal inline citations to the exact RFC section(s) that justify each requirement or gap.

QUALITY GATES:

- Coverage: transport (frames/ACK), TLS binding (HP/keys/Key Update), recovery/CC, PMTUD, migration.
- Safety: mention timing side‑channels for HP (§9.5) and AEAD usage limits (§6.6) when relevant. :contentReference[oaicite:146]{index=146} :contentReference[oaicite:147]{index=147}

NOTE: In repo, `gap_analysis.md` may be named `docs/GAP_ANALYSIS.md` or `docs/GAP.md`; update both if present to stay in sync.
