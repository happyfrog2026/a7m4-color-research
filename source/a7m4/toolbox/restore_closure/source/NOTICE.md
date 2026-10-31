# Closure helper source and provenance

The existing forward sound/WBI records are reused here. No new firmware
reverse-engineering, camera experiment or general-purpose root API is included.
The four WBI files are byte-identical copies of this research project's
existing M4 6.02 prepare/drop native code and pure host wire parsers;
`wbi-source-provenance.json` binds their original paths and SHA256 identities.
The small usr-ro helper is original MIT code derived from the previously
reviewed syscall, loader-identity and bounded-observation guards. Include
LICENSE.MIT with copies; it does not relicense camera images, snapshots,
keys, user data or third-party tools.

Copy only the files in closure-source-manifest.json. No complete firmware,
private WBI header, historic nonce/job or generated test ELF/cache is included.
The separate prior27-file source snapshot stays unchanged. WBI native code
has historical hardware evidence; the new usr-ro helper has offline ARM tests
only. A newly integrated product is not thereby hardware-validated.
