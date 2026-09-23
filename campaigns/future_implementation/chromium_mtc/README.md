# Chromium MTC integration

Goal: experimental Chromium integration using the validated BoringSSL MTC port.

Initial milestone:
1. Identify where Chromium configures client-side BoringSSL.
2. Identify SSL_CTX / SSL creation and verification configuration.
3. Determine how to enable experimental MTC negotiation.
4. Configure native trust_anchors (provisional 0xca34) in ClientHello.
5. Confirm the historical private 0xffa7 is not emitted. Do not patch Chromium
   to negotiate the old laboratory codepoint; this is not a final IANA assignment.

Out of scope for this milestone:
- MTC certificate verification
- Chromium certificate policy integration
- trust-anchor retry
- resumption
- client authentication
- performance campaigns