# Fixed resource worker source

Original toolbox code and SHA-256 implementation are covered by the repository
MIT license. `resource-worker.c` and `resource-sha256.h` are exact canonical
copies of the packaged sources in `a7m4/toolbox/data/`.

The source contains no Sony resource data or camera-specific preimages.
`resource-plan.h` and the resulting worker are generated privately from a
verified local capture and are not prebuilt release assets. Every dynamic
worker must remain below 65536 bytes. Software tests use an in-memory syscall
model; physical device validation is not performed by those tests.
