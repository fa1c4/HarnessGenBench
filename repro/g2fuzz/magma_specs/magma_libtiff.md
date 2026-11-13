# G2Fuzz MAGMA target: `libtiff`

- MAGMA target: `libtiff`, program `tiff_read_rgba_fuzzer`
- Format: TIFF/GeoTIFF image file
- Paper alignment: upstream G2Fuzz maps `tiff_read_rgba_fuzzer` to `tiff`;
  paper-faithful binary-format cell.
- Generator focus: classic little/big-endian TIFF headers, IFD chains, strips
  and tiles, PhotometricInterpretation, BitsPerSample/SamplesPerPixel,
  compression schemes (none/LZW/PackBits/Deflate), ExtraSamples, and
  SubIFDs.
