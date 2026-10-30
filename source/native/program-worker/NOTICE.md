This bounded AP/CP worker is derived from the repository's
native/service-fl23-direct/program.c and native/pin-sound-dynamic/program.c.
Those retain the MIT adaptation of QAQLeonard/a7c2-fl23-research,
src/fl23/native/installer.c at 782785641ca9f8b984940c7274b48706219e0da4.
The upstream license is included in LICENSE.C2.

New changes: 64-byte full-plan-ID request, variable-window source-identical
AP private-page COW, fixed AP/CP paths only, per-chip fsync/readback ordering,
fresh native space receipts, and no automatic failure inverse. No firmware
image, camera credential, generated private plan or historical session is
included. Host full-file verification and supervised physical validation
remain required. The source is an offline candidate, not hardware acceptance.
