# Brag Plan: TraceWeave

## What is this app?
TraceWeave turns heterogeneous security logs into a deterministic, provenance-backed investigation: chronology, claims, graph relationships, integrity hashes, and explicit findings.

## The angle
A serious incident-response control room that refuses to hallucinate. The joke is the restraint: every impressive claim immediately points back to raw evidence.

## Hook (first 2-3 seconds)
Large type: `DON'T TRUST THE TIMELINE.` A raw evidence line slams into a dark forensic canvas, then a green `CHAIN VERIFIED` stamp appears.

## Key moments (the middle)
- Upload evidence becomes a normalized chronology with source and line provenance.
- Claims split into Observed and Inferred instead of pretending they are the same.
- The relationship map connects login, actor, IP, and destination; findings call out contradictions and gaps.

## Outro / punchline
`Evidence before conclusions.` Then: `TraceWeave — investigate what the data can actually prove.`

## User flow worth showing
Entry → select/load the Generated attack scenario → inspect chronology → click through claims and relationship map → review findings/export report.

## Tone
- Preset: polished
- Creative direction: forensic product film with a dry, evidence-first punchline
- Interpretation: restrained dark UI, sharp amber/green accents, fast but readable reveals, no invented product metrics.

## Format: landscape — 1920x1080
## Duration: 20 seconds

## Visual identity (from the project)
- Background: #0b0d10
- Accent: amber #f2c46d and cyan #6fd3e8
- Text: #e8e6e1
- Display font: system sans-serif, heavy tracking and condensed uppercase labels
- Body font: system sans-serif
- Strongest visual element: the evidence workbench with chronology, claims, relationship map, and review queue

## Share copy (draft)
TraceWeave turns raw security logs into an evidence-backed timeline, graph, and review queue — with every conclusion tied back to the source record.

## Audio direction
- Role: intentional silence with crisp UI-like motion; no provider or audio asset is available in this local run.
- Music: none
- Music treatment: none
- Music cue guidance: unavailable; preserve readable holds.
- Audio-reactive treatment: none
- SFX posture: none
- Audio-coupled moments: none
- Restraint rule: visual clarity over synthetic audio.

## Storyboard

### Scene 1 — Evidence, not vibes — 3.0s
Dark forensic canvas. `DON'T TRUST THE TIMELINE.` appears in two lines; a raw log line scrolls beneath it. A small amber label reads `TRACEWEAVE / DETERMINISTIC RECONSTRUCTION`.
Sequential/interaction: raw line enters after the headline.
Audio intent: silent.
Audio-coupled idea: none.
Transition mood: hard cut → Scene 2

### Scene 2 — Normalize the source — 4.0s
A recreated TraceWeave shell slides in. Three source chips appear: `auth.jsonl`, `application.audit`, `network.csv`. The event ledger fills with `login`, `read`, and `network` rows, each showing source and line metadata.
Sequential/interaction: three rows reveal one by one, then hold.
Audio intent: silent.
Audio-coupled idea: none.
Transition mood: clean slide → Scene 3

### Scene 3 — Claims stay honest — 4.0s
The Claims panel expands. A yellow `Observed` claim and blue `Inferred` claim sit side by side. A provenance drawer shows `raw line → sha256 → chain link`.
Sequential/interaction: observed card first, inferred card second, provenance strip last.
Audio intent: silent.
Audio-coupled idea: none.
Transition mood: soft crossfade → Scene 4

### Scene 4 — See the connections — 5.0s
Relationship map animates in with nodes for `login-1`, `alice`, `10.0.0.1`, `net-1`, and `10.0.0.9`. Lines draw between them. A finding card appears: `CHAIN VERIFIED` and `0 unresolved sources`.
Sequential/interaction: nodes assemble from the center; links draw after nodes.
Audio intent: silent.
Audio-coupled idea: none.
Transition mood: dramatic zoom → Scene 5

### Scene 5 — Evidence before conclusions — 4.0s
The full workbench returns. Three labels lock in: `OBSERVED`, `INFERRED`, `UNKNOWN`. Final line: `TraceWeave — investigate what the data can actually prove.`
Sequential/interaction: labels arrive one by one, final lockup holds.
Audio intent: silent.
Audio-coupled idea: none.
Transition mood: clean hold → end
