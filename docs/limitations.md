# Limitations

The library does not reliably detect names, addresses, medical information,
or confidential free text. Obfuscated, split, encoded, and encrypted secrets
are out of scope. Context-dependent PII, non-English formats, non-US
identifiers, OCR, XML, and full YAML are not supported.

Structured YAML support is line-based only; anchors, multiline scalars, and
flow style are out of scope. Normalization is disabled because no safe
normalized-to-original byte mapping is currently shipped. Entropy detection
trades recall against false positives. The evaluation corpus is synthetic and
does not predict production precision or recall. This library is not a DLP
guarantee; policy misconfiguration can change outcomes.
