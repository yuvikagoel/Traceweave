# Hyperframes Composition Brief: TraceWeave

## Objective
Create a 20-second polished launch/demo video showing the real TraceWeave investigation flow: evidence intake, chronology, claim epistemics, relationship graph, and findings.

## Output
- Composition directory: `brag-output-2026-10-20-171527/composition/`
- Intended rendered video: `brag-output-2026-10-20-171527/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 20 seconds

## Source material
- Project root: repository root
- Primary files read: `README.md`, `web/app/page.tsx`, `web/app/styles.css`, `api/app.py`, engine parsers/models/pipeline
- Product name: TraceWeave
- Strongest claim: evidence before conclusions
- Key UI: chronology, claim inspector, relationship map, review queue
- Copy that must appear verbatim or as grounded labels:
  - Evidence before conclusions.
  - Observed / Inferred / Unknown
  - Chain verified
  - Chronological evidence

## Creative direction
- Tone preset: polished
- Creative direction: forensic product film with a dry evidence-first punchline
- Angle: show TraceWeave doing the work, not just describing a generic security dashboard.
- Hook: Don't trust the timeline.
- Outro: Evidence before conclusions.
- Avoid: invented metrics, generic SaaS claims, customer data, secrets, or abstract filler.

## Visual identity
- Background: `#0b0d10`
- Text: `#e8e6e1`
- Accent: `#f2c46d`, `#6fd3e8`, `#83d69a`
- Font: local system sans-serif fallback for reproducibility
- Visual references: the dark workbench, amber kicker labels, cyan inferred claims, green integrity status

## Storyboard
Use `brag-plan.md` as the creative contract. The composition recreates real UI concepts from the source app using fictional/synthetic IDs from the bundled demo dataset.

## Audio
- Audio role: intentional silence; no audio assets are required.
- Audio arc: visual-only, with readable holds.
- Music: none; no local music asset was available.
- Audio-reactive treatment: none.
- SFX: none.

## HyperFrames instructions
- Use one paused GSAP timeline registered as `window.__timelines["main"]`.
- Keep every major text element readable.
- Use deterministic motion only; no clocks, random values, network calls, or runtime measurements.
- Run `npx hyperframes check` before any render.
- Render locally only; do not publish or upload.
