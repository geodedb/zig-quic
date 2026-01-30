# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Email security concerns to: security@codepros.dev
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Security Measures

This project implements the following security measures:

### CI/CD Security Scanning
- **SAST**: Static Application Security Testing via GitLab
- **Secret Detection**: Automated scanning for hardcoded secrets
- **License Scanning**: Compliance verification for dependencies
- **Gitleaks**: Enhanced secrets detection

### Code Security
- Memory-safe Zig implementation
- No external C dependencies (stdlib only)
- Compile-time safety checks enabled
- Fuzz testing for parser inputs

### Release Security
- All releases are tagged and signed
- SPDX license identifiers in all source files
- Apache-2.0 license

## Known Security Limitations

The following security features are not yet implemented. Users should be aware of these limitations when deploying this implementation:

### Certificate Revocation (OCSP/CRL)

**Status:** Not Implemented

This implementation does not currently support:
- **OCSP (Online Certificate Status Protocol)** - RFC 6960
- **OCSP Stapling** - RFC 6066
- **CRL (Certificate Revocation Lists)** - RFC 5280

**Impact:** If a certificate authority revokes a certificate (e.g., due to key compromise), this implementation will continue to accept the revoked certificate until it expires naturally.

**Recommendation for high-security deployments:**
- Use short-lived certificates (e.g., 90 days or less)
- Implement certificate pinning at the application layer
- Monitor for certificate revocation events via external means
- Consider using a TLS-terminating proxy that supports OCSP/CRL

**Tracking:** This limitation is tracked in the implementation roadmap.

### Test Certificates

**WARNING:** Test certificates are generated locally under `tests/certs/` and `examples/interop/certs/`.
They are self-signed, not suitable for production, and are intentionally excluded from version control.

Always use properly issued certificates from a trusted CA in production deployments.

## Security Updates

Security updates will be released as patch versions. Subscribe to releases to be notified.
