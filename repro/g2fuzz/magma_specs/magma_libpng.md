# G2Fuzz MAGMA target: `libpng`

- MAGMA target: `libpng`, program `libpng_read_fuzzer`
- Format: PNG still image (IHDR/PLTE/tRNS/IDAT/IEND chunks)
- Paper alignment: upstream G2Fuzz `program_to_format.json` maps
  `libpng_read_fuzzer` to `png`; this is a paper-faithful binary-format cell.
- Generator focus: valid colour types and bit depths, palette/transparency,
  ancillary chunks (tEXt/zTXt/iTXt, pHYs, gAMA, cHRM, sRGB, iCCP, bKGD, tIME,
  sBIT, sPLT, hIST), interlacing, filter methods and multiple IDAT chunks.
- The generated files are used as the MAGMA `libpng_read_fuzzer` seed corpus.
