Whitebox custodian tables for the npvtunnel "wbaes-ctr-sha256" app key.

The tyboxes / mbl / xor tables are shared across app builds. Only tboxes_last
changes per build, so each `tboxes_last*.bin` below corresponds to one app
version's custodian whitebox.

Files
  tyboxes.bin        16384  16*256 uint32 big-endian, round-1 ty boxes
  mbl.bin            16384  16*256 uint32 big-endian, round-1 mixing box layer
  xor.bin            24576  96*16*16 byte xor tables
  tboxes_last.bin     4096  16*256 byte last-round tables (build v1)
  tboxes_last_v2.bin  4096  16*256 byte last-round tables (build v2, npvt)

To add support for a new build: extract `xh/b.java` (tboxesLast) from its
decompiled sources, serialize it as 16*256 bytes, drop it here as
`tboxes_last_v3.bin`, then append `&wbTlastV3` to `wbVariants()` in
`npvs_wb.go`.
