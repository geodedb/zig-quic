# Requirements Mirror

Generated: 2026-04-25

GitLab issues are the authoritative source of truth for requirements and gap status. This file is a flatfile mirror for humans and coding agents. Do not treat this file as authoritative when it disagrees with GitLab.

- Project: https://gitlab.com/devnw/zig/quic
- Issues: https://gitlab.com/devnw/zig/quic/-/issues
- Open gaps: `docs/GAP_ANALYSIS.md`
- Resolved gaps: `docs/GAP_ANALYSIS_RESOLVED.md`

## Verification Snapshot

- Toolchain evidence: `.gitlab-ci.yml:37-38` sets `ZIG_VERSION: "0.16.0"`; local `zig version` returned `0.16.0`.
- Formatting evidence: `zig fmt --check build.zig lib.zig quic.zig src tests benchmarks cmd tools clients examples fuzz` exited `0`.
- Test evidence: `zig build test` exited `0` on 2026-04-25, but emitted `ERROR: quic_client: connectEx requires a CA certificate (use connectInsecure for insecure testing)` from the test binary, so the diagnostic should be investigated before treating test output as fully clean.
- Focused closure evidence: `zig build -Dtest-filter=stream_edges test`, `zig build -Dtest-filter=packet_pool test`, `zig build -Dtest-filter=h3_error test`, `zig build -Dtest-filter=h3_loopback test`, `zig build -Dtest-filter=api_colocated test`, `zig build -Dtest-filter=disable_active_migration test`, `zig build -Dtest-filter=v2_packet_types test`, `zig build -Dtest-filter=pmtud test`, `zig build -Dtest-filter=handshake_error test`, `zig build -Dtest-filter=version_negotiation test`, and `bash -n interop/run_endpoint.sh` exited `0` on 2026-04-25.
- Coverage caveat: `rg --hidden --glob '!.git/**' --glob '!.claude/worktrees/**' --glob '*.zig' -n 'return error\.SkipZigTest' tests src | wc -l` returned `528`.

## Open Requirement Issues

These are open GitLab issues with requirement-like labels (`type::*`) and no `gap` label, grouped by component/intent. Implementation status is on the linked issue; this mirror does not assert completion.

### Transport, Protocol, and Interop

- [#5 Run full interop test suite against all implementations](https://gitlab.com/devnw/zig/quic/-/issues/5) - `component::interop`, `type::test`, `priority::high`
- [#7 Ensure transport parameter compatibility](https://gitlab.com/devnw/zig/quic/-/issues/7) - `component::interop`, `type::test`, `priority::high`
- [#8 Document implementation-specific quirks and workarounds](https://gitlab.com/devnw/zig/quic/-/issues/8) - `component::interop`, `type::docs`, `priority::medium`
- [#16 Add metrics and observability support](https://gitlab.com/devnw/zig/quic/-/issues/16) - `component::transport`, `type::feature`, `priority::medium`
- [#20 Implement Multipath QUIC support](https://gitlab.com/devnw/zig/quic/-/issues/20) - `component::transport`, `type::feature`, `priority::low`
- [#22 Implement QUIC-LB for load balancing](https://gitlab.com/devnw/zig/quic/-/issues/22) - `component::transport`, `type::feature`, `priority::low`
- [#27 Platform parity testing and validation](https://gitlab.com/devnw/zig/quic/-/issues/27) - `component::platform`, `type::test`, `priority::medium`
- [#32 Create and maintain RFC 9000/9001/9002 compliance checklist](https://gitlab.com/devnw/zig/quic/-/issues/32) - `component::transport`, `type::docs`, `priority::medium`
- [#34 CI/CD improvements and automation](https://gitlab.com/devnw/zig/quic/-/issues/34) - `component::cli`, `type::enhancement`, `priority::medium`

### Streams

- [#23 Implement complete stream state machine per RFC 9000 S3](https://gitlab.com/devnw/zig/quic/-/issues/23) - `component::streams`, `type::feature`, `priority::high`
- [#24 Implement RESET_STREAM and STOP_SENDING end-to-end](https://gitlab.com/devnw/zig/quic/-/issues/24) - `component::streams`, `type::feature`, `priority::high`
- [#25 Implement dynamic MAX_DATA/MAX_STREAM_DATA thresholds](https://gitlab.com/devnw/zig/quic/-/issues/25) - `component::streams`, `type::enhancement`, `priority::medium`
- [#30 Create comprehensive stream unit test suite](https://gitlab.com/devnw/zig/quic/-/issues/30) - `component::streams`, `type::test`, `priority::high`
- [#31 Create stream integration test suite](https://gitlab.com/devnw/zig/quic/-/issues/31) - `component::streams`, `type::test`, `priority::high`

### TLS, Crypto, and Security

- [#6 Validate cipher suite negotiation across implementations](https://gitlab.com/devnw/zig/quic/-/issues/6) - `component::interop`, `type::test`, `priority::high`
- [#17 Security audit of crypto operations](https://gitlab.com/devnw/zig/quic/-/issues/17) - `component::tls`, `type::security`, `priority::critical`
- [#18 Comprehensive fuzz testing for all parsers](https://gitlab.com/devnw/zig/quic/-/issues/18) - `component::transport`, `type::security`, `priority::high`
- [#29 Enhanced certificate chain validation with OCSP/CRL support](https://gitlab.com/devnw/zig/quic/-/issues/29) - `component::tls`, `type::security`, `priority::medium`
- [#33 Audit and verify constant-time crypto operations](https://gitlab.com/devnw/zig/quic/-/issues/33) - `component::crypto`, `type::security`, `priority::high`

### HTTP/3

- [#28 Implement HTTP/3 with dynamic QPACK table](https://gitlab.com/devnw/zig/quic/-/issues/28) - `component::h3`, `type::feature`, `priority::medium`

### Recovery, Performance, and Memory

- [#9 Optimize packet processing paths](https://gitlab.com/devnw/zig/quic/-/issues/9) - `component::transport`, `type::enhancement`, `priority::medium`
- [#10 Improve memory allocation patterns](https://gitlab.com/devnw/zig/quic/-/issues/10) - `component::transport`, `type::enhancement`, `priority::medium`
- [#11 Implement zero-copy packet processing where possible](https://gitlab.com/devnw/zig/quic/-/issues/11) - `component::transport`, `type::enhancement`, `priority::medium`
- [#13 Implement connection pooling](https://gitlab.com/devnw/zig/quic/-/issues/13) - `component::transport`, `type::feature`, `priority::low`
- [#21 Implement BBR congestion control algorithm](https://gitlab.com/devnw/zig/quic/-/issues/21) - `component::recovery`, `type::feature`, `priority::medium`
- [#109 No STREAM frame coalescing or GSO - 1 frame per UDP send](https://gitlab.com/devnw/zig/quic/-/issues/109) - `component::transport`, `type::enhancement`, `priority::high`
- [#154 Connection lookup O(N) full-table scan per packet in findConnectionByDcid](https://gitlab.com/devnw/zig/quic/-/issues/154) - `component::endpoint`, `type::bug`, `priority::critical`
- [#158 Pacing timer truncated to 1ms granularity - non-functional above about 10 Mbps](https://gitlab.com/devnw/zig/quic/-/issues/158) - `component::endpoint`, `type::bug`, `priority::high`
- [#160 Recovery mutex critical section blocks all CC reads during ACK processing](https://gitlab.com/devnw/zig/quic/-/issues/160) - `component::recovery`, `type::enhancement`, `priority::high`
- [#165 One syscall per packet send - sendBatch/sendmmsg exists but unused on data path](https://gitlab.com/devnw/zig/quic/-/issues/165) - `component::transport`, `type::enhancement`, `priority::high`
- [#167 64KB PacketBufferPool per connection](https://gitlab.com/devnw/zig/quic/-/issues/167) - `component::transport`, `type::enhancement`, `priority::high`
- [#170 Double Initial packet encoding - 2x AEAD cost per client Initial](https://gitlab.com/devnw/zig/quic/-/issues/170) - `component::transport`, `type::bug`, `priority::high`
- [#172 ECN bits not extracted - hardcoded to 0, recvmsg path disabled](https://gitlab.com/devnw/zig/quic/-/issues/172) - `component::endpoint`, `type::bug`, `priority::high`
- [#182 Timer O(N) + PTO polling](https://gitlab.com/devnw/zig/quic/-/issues/182) - `component::endpoint`, `type::enhancement`, performance
- [#183 Send path efficiency - pacing heap alloc per packet, no sendmmsg batching](https://gitlab.com/devnw/zig/quic/-/issues/183) - `component::endpoint`, `type::enhancement`, performance

### Docs and Quality

- [#14 Add comprehensive error handling framework](https://gitlab.com/devnw/zig/quic/-/issues/14) - `component::transport`, `type::enhancement`, `priority::high`
- [#15 Implement proper logging framework](https://gitlab.com/devnw/zig/quic/-/issues/15) - `component::transport`, `type::feature`, `priority::high`
- [#19 Comprehensive documentation improvements](https://gitlab.com/devnw/zig/quic/-/issues/19) - `type::docs`, `priority::medium`
- [#115 Connection struct is large and non-domain-aligned](https://gitlab.com/devnw/zig/quic/-/issues/115) - `component::transport`, `type::refactor`, `priority::low`

## Open Gap Issues

Open gaps are mirrored in `docs/GAP_ANALYSIS.md`; GitLab remains authoritative.

- [GAP-0004 #88](https://gitlab.com/devnw/zig/quic/-/issues/88) - 528 test stubs return `SkipZigTest`
- [GAP-0007 #136](https://gitlab.com/devnw/zig/quic/-/issues/136) - crypto hardening audit incomplete
- [GAP-0009 #138](https://gitlab.com/devnw/zig/quic/-/issues/138) - version negotiation lacks end-to-end verification
- [GAP-0011 #140](https://gitlab.com/devnw/zig/quic/-/issues/140) - stream state machine uses boolean flags
- [GAP-0012 #141](https://gitlab.com/devnw/zig/quic/-/issues/141) - CID lifecycle lacks proactive integration
- [GAP-0013 #142](https://gitlab.com/devnw/zig/quic/-/issues/142) - full crypto hardening pass needed
- [GAP-0014 #143](https://gitlab.com/devnw/zig/quic/-/issues/143) - stream state machine needs explicit model
- [GAP-0015 #144](https://gitlab.com/devnw/zig/quic/-/issues/144) - RESET_STREAM/STOP_SENDING integration tests needed
- [GAP-0016 #146](https://gitlab.com/devnw/zig/quic/-/issues/146) - loss detection edge cases untested
- [GAP-0017 #148](https://gitlab.com/devnw/zig/quic/-/issues/148) - conflicting CUBIC implementations remain
- [GAP-0045 #152](https://gitlab.com/devnw/zig/quic/-/issues/152) - path validation minimal
- [GAP-0053 #126](https://gitlab.com/devnw/zig/quic/-/issues/126) - endpoint mutex held during receive batch
- [GAP-0054 #129](https://gitlab.com/devnw/zig/quic/-/issues/129) - connection allocations not pooled
- [GAP-0055 #188](https://gitlab.com/devnw/zig/quic/-/issues/188) - pre-Retry connection allocation exhaustion
- [GAP-0056 #191](https://gitlab.com/devnw/zig/quic/-/issues/191) - QNS container runtime user hardening needs verification
- [GAP-0058 #175](https://gitlab.com/devnw/zig/quic/-/issues/175) - deprecated/dead transport code remains
- [GAP-0060 #177](https://gitlab.com/devnw/zig/quic/-/issues/177) - non-domain method module naming
- [GAP-0061 #178](https://gitlab.com/devnw/zig/quic/-/issues/178) - minimum datagram size literal duplicated

## Resolved Gap Issues

Resolved gaps are mirrored in `docs/GAP_ANALYSIS_RESOLVED.md`. See closed GitLab issues for authoritative closure notes and evidence.
