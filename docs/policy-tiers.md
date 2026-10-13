# Policy and tiers

T0 is public, T1 personal, T2 confidential, T3 restricted, and T4 critical.
The default mapping is email/phone/public IP T1, internal IP T2, identifiers,
financial data, and tokens T3, and private keys/database credentials T4.

Rules match exact categories or `path.Match` globs, optional tier ranges and
contexts. Explicit priority wins; otherwise exact category beats glob, glob
beats tier-only, and tier-only beats default. Equal matches choose BLOCK,
RESTRICT, REDACT, then ALLOW, followed by rule order.

RESTRICT only returns `Restricted` and sorted unique `Conditions`; callers
enforce those conditions. BLOCK sets `Blocked` and omits sanitized text.
Policy JSON is strictly decoded with unknown fields rejected.
