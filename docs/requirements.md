# Requirements — QUIC v1 (Zig std‑only)

## Functional

- QUIC v1 transport (packets, frames, streams, flow control, errors) per RFC 9000 §2–§4, §12–§20; include ACK ranges + ECN counters (§19.3). :contentReference[oaicite:49]{index=49} :contentReference[oaicite:50]{index=50}
- Version negotiation, Retry, CONNECTION_CLOSE semantics (§6, §10–§11, §19.19). :contentReference[oaicite:53]{index=53} :contentReference[oaicite:54]{index=54}
- Path validation & migration (PATH_CHALLENGE/RESPONSE; preferred address) (§9, §19.17–§19.18).:contentReference[oaicite:55]{index=55} :contentReference[oaicite:57]{index=57} :contentReference[oaicite:58]{index=58}
- PMTUD/DPLPMTUD with ICMP validation (§14.2–§14.4). :contentReference[oaicite:61]{index=61} :contentReference[oaicite:62]{index=62}

## TLS 1.3 + QUIC‑TLS

- HKDF labels, Initial/Handshake/1‑RTT keys, header protection samples and PN masking per RFC 9001 §5.4–§5.5; follow examples A.1–A.5. :contentReference[oaicite:65]{index=65} :contentReference[oaicite:66]{index=66}
- Key Update sequencing & retention windows (§6.1–§6.5); AEAD usage limits (§6.6). :contentReference[oaicite:69]{index=69} :contentReference[oaicite:70]{index=70}
- Constant‑time behavior for HP timing side‑channels (§9.5). :contentReference[oaicite:72]{index=72}

## Recovery & Congestion Control

- PTO, persistent congestion, loss detection; NewReno default; **CUBIC** optional (`-Dcc=cubic`) per RFC 9002 (Sections 6–7; refs to RFC 8312). :contentReference[oaicite:75]{index=75} :contentReference[oaicite:76]{index=76}

## Non‑Functional

- Zig 0.14.1, **std‑only** cryptography; zeroization of retired keys; deterministic tests. Align with repo process gates and doc updates (GAP, NEXT). :contentReference[oaicite:78]{index=78}

## CLI/Tools/CI (minimum)

- `quic-varint` acceptance (encode/decode/underflow) and TLS key schedule KAT; CI on linux/windows/macos; doccheck; no Internet egress in tests. :contentReference[oaicite:80]{index=80}

> Source‑of‑truth: RFC 9000/9001/9002 + in‑repo QUIC brief. :contentReference[oaicite:81]{index=81} :contentReference[oaicite:82]{index=82} :contentReference[oaicite:83]{index=83}
