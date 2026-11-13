# G2Fuzz MAGMA target: `poppler`

- MAGMA target: `poppler`, program `pdf_fuzzer`
- Format: PDF document
- Paper alignment: the G2Fuzz upstream program map includes `pdf_fuzzer`
  (and `pdftotext`/`pdftoppm`); paper-faithful binary-format cell.
- Generator focus: header/version, indirect object graph, xref table or stream,
  trailer/startxref, page tree, content streams with text/graphics operators,
  fonts, images, annotations, and linearized versus classic layouts.
