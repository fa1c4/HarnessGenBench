# G2Fuzz MAGMA target: `openssl`

- MAGMA target: `openssl`, program `x509`
- Format: DER-encoded X.509 certificate, generated as a binary large object
- Paper alignment: the G2Fuzz upstream program map includes `x509` under the
  `binary_large_object_BLOB` format; paper-faithful binary-format cell.
- Generator focus: valid TBSCertificate structure, version/serial/signature
  algorithm OIDs, issuer/subject RDNSequences, validity times, SubjectPublicKeyInfo,
  extensions (SAN, key usage, basic constraints, CRL distribution points),
  and multiple signature algorithms.
