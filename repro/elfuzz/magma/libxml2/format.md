# XML input format for MAGMA `libxml2`

The target is `libxml2_xml_read_memory_fuzzer`, which feeds the input bytes to
`xmlReadMemory` (the committed entry API).  The input is a text XML document.

Characteristics worth covering:

* prolog: optional XML declaration such as `<?xml version="1.0"?>`
* elements, attributes, namespaces (`xmlns`), and nested children
* text nodes, CDATA sections, comments, and processing instructions
* entity and character references (`&amp;`, `&#x41;`)
* a DOCTYPE declaration, optionally with an internal subset
* malformed but still parseable variants (unclosed tags, unknown entities)

The initial seed program returns a small well-formed document.  ELFuzz mutates
the generator program, not the target harness.
