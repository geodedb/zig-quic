## GAP Analysis for QUIC Implementation

This document summarises the current state of the QUIC transport
implementation provided in `quic.zig` and identifies major areas
that remain incomplete relative to the specification defined in RFC 9000
and its companion RFC 9001 (cryptographic handshake).

### Implemented Features

- **Variable‑length integers**:  Encoding and decoding of QUIC’s bespoke
  variable‑length integer format (Section 16) are fully supported.
- **Frame definitions**:  All frame types defined in RFC 9000 are
  represented by the `Frame` union, with fields matching those in the
  specification.  The `writeFrame` function serialises these frames
  into a writer, emitting the correct type byte and encoding fields
  using the shortest possible form【256754717438045†L4393-L4400】.
- **Packet encoding**:  A minimal packet structure (`Packet`) can
  serialise multiple frames into a short‑header packet.  Packet
  numbers are encoded as full variable‑length integers for simplicity.
- **Unit tests**:  A suite of tests exercises variable‑length integer
  encoding and each frame type, ensuring that type values and
  associated fields are encoded correctly.
- **Cryptographic stub**:  A placeholder `protect` method is present
  to demonstrate how authenticated encryption (AES‑GCM) might be
  integrated.  It derives a nonce by XORing the packet number into the
  provided initialisation vector and uses `std.crypto.aead` for the
  underlying cipher.  Error handling is provided for invalid key or
  nonce lengths.

### Missing Functionality

Despite these basic capabilities, the implementation is far from a
complete QUIC stack.  Significant gaps include:

1. **Packet protection and header protection**:  Real QUIC packets
   derive keys and nonces from TLS, truncate packet numbers and apply
   header protection using an AEAD tag.  The current `protect` method
   does not perform key derivation, header protection or truncate
   packet numbers.  It also makes simplifying assumptions about nonce
   construction that violate RFC 9001.  A complete implementation
   must incorporate TLS 1.3 handshake logic and follow the key
   schedule defined in RFC 9001.

2. **Packet parsing and frame decoding**:  While frames can be
   encoded, there is no corresponding logic to parse incoming packets
   or decode frames.  Implementing robust parsing requires handling
   variable‑length integers, enforcing limits, validating reserved
   bits and recognising unknown extensions.

3. **ACK ranges and ECN**:  The ACK frame support encodes only a
   single range with no ECN counters.  RFC 9000 allows multiple
   acknowledgement ranges and optional ECN information.  Extending the
   `ack` variant to include a list of ranges and ECN counts is
   necessary for interoperability.

4. **Flow control and loss recovery**:  QUIC’s transport layer
   includes sophisticated flow control, congestion control and loss
   recovery algorithms.  This implementation does not track flow
   control limits, manage retransmissions or implement any form of
   congestion control.

5. **Stream lifecycle management**:  Streams must transition through
   states (idle, open, half‑closed, closed), handle reset signals,
   enforce ordering and respect stream prioritisation.  The current
   code treats streams as raw payload carriers without state.

6. **Connection management**:  Features such as version negotiation,
   connection ID handling, stateless resets, migration, and path
   validation are unimplemented.  The `new_connection_id` and
   `retire_connection_id` frames can be encoded but there is no logic
   to manage connection identifiers or handle migration events.

7. **Security considerations**:  QUIC relies on TLS 1.3 for
   encryption and authentication, with a complex handshake and key
   update mechanism.  None of the handshake, certificate validation
   or key update logic exists in this code.  Additionally, header
   protection, which masks portions of the packet header to thwart
   certain attacks, is absent.

8. **Error handling and transport parameters**:  The implementation
   defines only a few error types and does not support transport
   parameters negotiation.  Proper error handling requires detailed
   error codes, including those for application‑level errors.

### Next Steps

To progress towards a complete QUIC implementation, subsequent
iterations should focus on:

1. **Implementing frame parsing**:  Add functions to read frames from
   a byte stream, populating the `Frame` union and validating
   encodings.  Decoding should handle all frame types and unknown
   frames gracefully.
2. **Integrating TLS 1.3**:  Establish a TLS handshake using Zig’s
   `std.crypto.tls` (when available) or an external library, derive
   initial secrets and implement the key schedule for different
   encryption levels.
3. **Header protection**:  Apply the header protection mask to the
   packet number and type fields as described in RFC 9001.  This
   includes maintaining separate keys for header and payload
   protection.
4. **State machines**:  Model connection and stream state machines
   (opening, closing, draining), implement flow control and respect
   prioritisation.
5. **Loss recovery**:  Incorporate timers, congestion control and
   retransmission strategies, following the algorithms outlined in
   RFC 9002.
6. **Extensive testing and interoperability**:  Augment unit tests
   with property‑based tests, fuzzing and, ideally, interop testing
   against existing QUIC implementations to verify compliance.

This gap analysis should serve as a roadmap for future work.  The
current code offers a foundation for experimentation and learning
about QUIC framing and variable‑length integers, but a production‑ready
transport will require significant additional development.