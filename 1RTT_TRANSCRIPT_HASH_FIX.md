# Critical 1-RTT Transcript Hash Fix

## Issue

The QUIC server was unable to decrypt 1-RTT packets from clients because application traffic secrets were being derived with an **incorrect transcript hash**.

## Root Cause

According to RFC 8446 §7.1, both `client_application_traffic_secret_0` and `server_application_traffic_secret_0` must be derived from the transcript hash:

```
ClientHello...server Finished
```

**NOT** including the client Finished message.

### What Was Wrong

**Before the fix:**

```zig
// In tls13.zig onCryptoRecv() when processing peer Finished:
if (ok) {
    // Add peer Finished to transcript
    self.transcript.update(finished_msg);

    // Then compute app secrets (WRONG - transcript now includes peer Finished)
    _ = self.computeApplicationSecrets();
}
```

This caused:

- **Server:** transcript = CH...SH...EE...Cert...CV...server Finished...client Finished → **WRONG!**
- **Client:** transcript = CH...SH...EE...Cert...CV...server Finished → **Correct only by accident**

The server was deriving application secrets with the client Finished included, while clients (and the TLS spec) expect it to be derived without client Finished.

## The Fix

**After the fix:**

```zig
// In tls13.zig onCryptoRecv() when processing peer Finished:
if (ok) {
    // Derive application secrets FIRST (before adding peer Finished)
    // At this point: transcript = CH...SH...EE...Cert...CV...server Finished ✅
    std.debug.print("TLS: Deriving application traffic secrets (before adding peer Finished to transcript)\n", .{});
    _ = self.computeApplicationSecrets();

    // THEN add peer Finished to transcript (for resumption master secret)
    self.transcript.update(finished_msg);
}
```

Now both client and server derive application secrets with the same transcript hash:

```
ClientHello...ServerHello...EncryptedExtensions...Certificate...CertificateVerify...server Finished
```

## Impact

This fix resolves:

- ✅ 1-RTT AEAD decryption failures
- ✅ Client timeout issues when waiting for server responses
- ✅ Bi-directional streaming over QUIC

## Verification

The fix ensures that:

1. Server derives app secrets before receiving client Finished
2. Client derives app secrets before sending its own Finished
3. Both sides use identical transcript hashes
4. Application keys match, enabling successful 1-RTT encryption/decryption

## RFC Reference

RFC 8446 Section 7.1 - Key Schedule:

```
+-----> Derive-Secret(., "c ap traffic",
|                     ClientHello...server Finished)
|                     = client_application_traffic_secret_0
|
+-----> Derive-Secret(., "s ap traffic",
|                     ClientHello...server Finished)
|                     = server_application_traffic_secret_0
```

Note: The resumption master secret (used for 0-RTT) uses "ClientHello...client Finished", but application secrets do not.
