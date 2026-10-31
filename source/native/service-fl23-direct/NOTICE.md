# Source attribution

`program.c` adapts the inode-preserving window installer in
QAQLeonard/a7c2-fl23-research, commit
`782785641ca9f8b984940c7274b48706219e0da4`,
`src/fl23/native/installer.c` (SHA-256
`a73aec5e12c76d5c6450822b1d8b9b2b4b0d9f252b222218e392e6bffcba2478`).
The upstream MIT notice is preserved verbatim in `LICENSE.C2`.

M4 changes: pinned host manifest, fixed paths and R018 mount guards;
32-byte nonce-bearing request and 184-byte result; exclusive result creation;
CP-only avoids `/usr` remount; inspect-target action; no-follow file opens;
request EOF, window and FD checks; separate mount/rollback outcomes.

New host helpers and tests do not embed complete firmware. Generated private
headers and workers contain user-supplied firmware excerpts and remain under
private Mac local/session/temp directories; they must not enter a source or
release package. Sony data retains its original rights.
