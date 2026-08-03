# curl_curl_fuzzer_http format

Inputs are HTTP response texts as parsed by curl's fuzzer: a status line (`HTTP/<ver> <code> <reason>\r\n`), zero or more `Header: value\r\n` lines, a blank line, then an optional body. HGB extension profile reuses the ELFuzz text-input evolution space bound to the native curl_curl_fuzzer_http binary.
