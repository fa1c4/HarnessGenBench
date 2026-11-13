# G2Fuzz MAGMA target: `libxml2`

- MAGMA target: `libxml2`, program `libxml2_xml_read_memory_fuzzer`
- Format: text XML document
- Method profile: extension (the G2Fuzz upstream program map has no
  `libxml2_xml_read_memory_fuzzer` entry; the format is fully within G2Fuzz's
  format-directed input-generator method).
- Generator focus: prolog/declaration, namespaces, nested elements and
  attributes, text/CDATA/comments/processing instructions, entity and character
  references, DOCTYPE with an internal subset, and parseable malformed input.
