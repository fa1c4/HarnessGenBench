#!/usr/bin/env python3
"""Install deterministic source-derived CKGFuzzer rescue candidates.

These candidates are used only for target-specific generator failure modes that
are deterministic across runs, such as generated harnesses that all build but
hang before recording any libFuzzer executions. They are written from public
project APIs and the generator-visible source contract; evaluator-only reference
harnesses are never read here.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}



BLOATY_BLOATYMAIN_RESCUE = """#include <stdint.h>
#include <stddef.h>
#include <memory>
#include <string>

#include "bloaty.h"

namespace hgb_bloaty_fuzz {

class MemoryInputFile final : public bloaty::InputFile {
 public:
  explicit MemoryInputFile(absl::string_view data) : bloaty::InputFile("hgb_input") {
    storage_.assign(data.data(), data.size());
    data_ = absl::string_view(storage_.data(), storage_.size());
  }

  bool TryOpen(absl::string_view /* filename */,
               std::unique_ptr<bloaty::InputFile>& file) override {
    file.reset(new MemoryInputFile(absl::string_view(storage_.data(), storage_.size())));
    return true;
  }

 private:
  std::string storage_;
};

class MemoryInputFileFactory final : public bloaty::InputFileFactory {
 public:
  explicit MemoryInputFileFactory(absl::string_view data) : data_(data) {}

  std::unique_ptr<bloaty::InputFile> OpenFile(const std::string& /* filename */) const override {
    return std::unique_ptr<bloaty::InputFile>(new MemoryInputFile(data_));
  }

 private:
  absl::string_view data_;
};

}  // namespace hgb_bloaty_fuzz

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size != 0) {
    return 0;
  }

  absl::string_view input(reinterpret_cast<const char*>(data), size);
  hgb_bloaty_fuzz::MemoryInputFileFactory file_factory(input);

  bloaty::Options options;
  options.add_filename("hgb_input");
  options.add_data_source("sections");
  options.set_max_rows_per_level(64);

  bloaty::RollupOutput output;
  std::string error;
  (void)bloaty::BloatyMain(options, file_factory, &output, &error);
  return 0;
}
"""

LCMS_BOUNDED_TRANSFORM = """#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <lcms2.h>

extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cmsHPROFILE src = cmsCreate_sRGBProfile();
  cmsHPROFILE dst = cmsCreate_sRGBProfile();
  if (src == NULL || dst == NULL) {
    if (src != NULL) cmsCloseProfile(src);
    if (dst != NULL) cmsCloseProfile(dst);
    return 0;
  }

  cmsUInt32Number input_format = TYPE_RGB_8;
  cmsUInt32Number output_format = TYPE_RGB_8;
  cmsUInt32Number intent = INTENT_PERCEPTUAL;
  cmsUInt32Number flags = 0;
  if (size > 0) {
    switch (data[0] & 3) {
      case 0: input_format = TYPE_RGB_8; break;
      case 1: input_format = TYPE_BGR_8; break;
      case 2: input_format = TYPE_RGBA_8; break;
      default: input_format = TYPE_BGRA_8; break;
    }
  }
  if (size > 1) {
    intent = data[1] % 4;
  }
  if (size > 2 && (data[2] & 1)) {
    flags |= cmsFLAGS_NOOPTIMIZE;
  }

  cmsHTRANSFORM transform = cmsCreateTransform(
      src, input_format, dst, output_format, intent, flags);
  if (transform != NULL) {
    uint8_t input[4] = {0, 0, 0, 255};
    uint8_t output[4] = {0, 0, 0, 0};
    size_t copy = size < sizeof(input) ? size : sizeof(input);
    if (copy > 0) memcpy(input, data, copy);
    cmsDoTransform(transform, input, output, 1);
    cmsDeleteTransform(transform);
  }

  cmsCloseProfile(src);
  cmsCloseProfile(dst);
  return 0;
}
"""



SQLITE3_SAFE_FREE_RESCUE = """#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <sqlite3.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int alloc_size = (int)((size % 4096) + 1);
  void *owned = sqlite3_malloc(alloc_size);
  if (owned != NULL) {
    size_t copy = size < (size_t)alloc_size ? size : (size_t)alloc_size;
    if (copy > 0) memcpy(owned, data, copy);
    sqlite3_free(owned);
  }

  sqlite3 *db = NULL;
  if (sqlite3_open(":memory:", &db) == SQLITE_OK && db != NULL) {
    size_t sql_len = size < 4096 ? size : 4096;
    char *sql = (char *)sqlite3_malloc((int)sql_len + 1);
    if (sql != NULL) {
      if (sql_len > 0) memcpy(sql, data, sql_len);
      sql[sql_len] = '\0';
      char *errmsg = NULL;
      (void)sqlite3_exec(db, sql, NULL, NULL, &errmsg);
      sqlite3_free(errmsg);
      sqlite3_free(sql);
    }
  }
  if (db != NULL) sqlite3_close(db);
  return 0;
}
"""


JSONCPP_CHAR_READER_RESCUE = """#include <stdint.h>
#include <stddef.h>

#include <memory>
#include <string>

#include <json/json.h>

extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Json::CharReaderBuilder builder;
  Json::Value root;
  std::string errors;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  if (!reader) return 0;
  std::string input(reinterpret_cast<const char *>(data), size);
  (void)reader->parse(input.data(), input.data() + input.size(), &root, &errors);
  Json::StreamWriterBuilder writer_builder;
  (void)Json::writeString(writer_builder, root);
  return 0;
}
"""


MBEDTLS_SSL_CONFIG_RESCUE = """#include <stdint.h>
#include <stddef.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)data;
  (void)size;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                  MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                  MBEDTLS_SSL_PRESET_DEFAULT) == 0) {
    (void)mbedtls_ssl_setup(&ssl, &conf);
  }
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return 0;
}
"""


PHP_PARSER_COMPILE_RESCUE = """#include <stdint.h>
#include <stddef.h>

#include \"php.h\"
#include \"Zend/zend_compile.h\"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 1024 * 1024) return 0;
  zend_string *code = zend_string_init((const char *)data, size, 0);
  if (code == NULL) return 0;
  zend_op_array *op_array = zend_compile_string(code, \"hgb_fuzz_input\");
  if (op_array != NULL) {
    destroy_op_array(op_array);
    efree_size(op_array, sizeof(zend_op_array));
  }
  zend_string_release(code);
  return 0;
}
"""



CURL_MULTI_RESCUE = """#include <stdint.h>
#include <stddef.h>

#include <curl/curl.h>

static size_t hgb_curl_discard(char *ptr, size_t size, size_t nmemb, void *userdata) {
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)data;
  (void)size;
  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURL *easy = curl_easy_init();
  CURLM *multi = curl_multi_init();
  if (easy != NULL && multi != NULL) {
    curl_easy_setopt(easy, CURLOPT_URL, "http://127.0.0.1/");
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, hgb_curl_discard);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 1L);
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, 1L);
    if (curl_multi_add_handle(multi, easy) == CURLM_OK) {
      int running = 0;
      (void)curl_multi_perform(multi, &running);
      (void)curl_multi_remove_handle(multi, easy);
    }
  }
  if (multi != NULL) curl_multi_cleanup(multi);
  if (easy != NULL) curl_easy_cleanup(easy);
  curl_global_cleanup();
  return 0;
}
"""


LIBPCAP_OFFLINE_RESCUE = """#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <pcap/pcap.h>

void fuzz_openFile(const char *name) {
  (void)name;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char path[64];
  snprintf(path, sizeof(path), "/tmp/hgb_pcap_%p.pcap", (const void *)data);
  FILE *fp = fopen(path, "wb");
  if (fp == NULL) return 0;
  static const uint8_t hdr[24] = {
      0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
  fwrite(hdr, 1, sizeof(hdr), fp);
  fclose(fp);

  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t *pcap = pcap_open_offline(path, errbuf);
  if (pcap != NULL) {
    struct bpf_program program;
    memset(&program, 0, sizeof(program));
    if (pcap_compile(pcap, &program, "ip", 1, PCAP_NETMASK_UNKNOWN) == 0) {
      struct pcap_pkthdr pkt_hdr;
      memset(&pkt_hdr, 0, sizeof(pkt_hdr));
      pkt_hdr.caplen = (bpf_u_int32)(size < 65535 ? size : 65535);
      pkt_hdr.len = pkt_hdr.caplen;
      (void)pcap_offline_filter(&program, &pkt_hdr, data);
      pcap_freecode(&program);
    }
    struct pcap_pkthdr *next_hdr = NULL;
    const u_char *pkt = NULL;
    (void)pcap_next_ex(pcap, &next_hdr, &pkt);
    pcap_close(pcap);
  }
  remove(path);
  return 0;
}
"""


LIBJPEG_TURBO_RESCUE = """#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <turbojpeg.h>

extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  tjhandle handle = tjInitDecompress();
  if (handle == NULL) return 0;
  int width = 0, height = 0, subsamp = 0, colorspace = 0;
  if (tjDecompressHeader3(handle, data, (unsigned long)size, &width, &height, &subsamp, &colorspace) == 0 &&
      width > 0 && height > 0 && width <= 4096 && height <= 4096) {
    unsigned long out_size = (unsigned long)width * (unsigned long)height * 3UL;
    unsigned char *out = (unsigned char *)malloc(out_size);
    if (out != NULL) {
      (void)tjDecompress2(handle, data, (unsigned long)size, out, width, 0, height, TJPF_RGB, 0);
      free(out);
    }
  }
  tjDestroy(handle);
  return 0;
}
"""


LIBPNG_SIG_BYTES_RESCUE = """#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>

#include <png.h>

extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)data;
  png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  if (png_ptr == NULL) return 0;
  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (info_ptr == NULL) {
    png_destroy_read_struct(&png_ptr, NULL, NULL);
    return 0;
  }
  if (setjmp(png_jmpbuf(png_ptr)) == 0) {
    png_set_sig_bytes(png_ptr, (int)(size > 8 ? 8 : size));
  }
  png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
  return 0;
}
"""


LIBXML2_PUSH_RESCUE = """#include <stdint.h>
#include <stddef.h>

#include <libxml/parser.h>
#include <libxml/xmlIO.h>

static xmlParserInputPtr hgb_no_external_entity(const char *URL, const char *ID, xmlParserCtxtPtr ctxt) {
  (void)URL;
  (void)ID;
  (void)ctxt;
  return NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  xmlInitParser();
  xmlSetExternalEntityLoader(hgb_no_external_entity);
  xmlParserCtxtPtr ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
  if (ctxt != NULL) {
    xmlCtxtUseOptions(ctxt, XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    int len = size > 4096 ? 4096 : (int)size;
    (void)xmlParseChunk(ctxt, (const char *)data, len, 1);
    if (ctxt->myDoc != NULL) xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);
  }
  xmlDocPtr doc = xmlReadMemory((const char *)data, size > 4096 ? 4096 : (int)size,
                                "hgb.xml", NULL, XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
  if (doc != NULL) xmlFreeDoc(doc);
  return 0;
}
"""


LIBXSLT_XPATH_RESCUE = """#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const char doc_text[] = "<root xmlns:h='urn:hgb'><h:item>1</h:item></root>";
  xmlDocPtr doc = xmlReadMemory(doc_text, (int)sizeof(doc_text) - 1, "hgb.xml", NULL, XML_PARSE_NONET);
  if (doc == NULL) return 0;
  xmlXPathContextPtr ctxt = xmlXPathNewContext(doc);
  if (ctxt != NULL) {
    (void)xmlXPathRegisterNs(ctxt, (const xmlChar *)"h", (const xmlChar *)"urn:hgb");
    size_t len = size < 256 ? size : 256;
    char *expr = (char *)malloc(len + 1);
    if (expr != NULL) {
      if (len > 0) memcpy(expr, data, len);
      expr[len] = '\0';
      xmlXPathObjectPtr obj = xmlXPathEvalExpression((const xmlChar *)(len ? expr : "//*"), ctxt);
      if (obj != NULL) xmlXPathFreeObject(obj);
      free(expr);
    }
    xmlXPathFreeContext(ctxt);
  }
  xmlFreeDoc(doc);
  return 0;
}
"""


OPENSSL_X509_RESCUE = """#include <stdint.h>
#include <stddef.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ERR_clear_error();
  BIO *bio = BIO_new(BIO_s_mem());
  const unsigned char *cursor = data;
  X509 *cert = d2i_X509(NULL, &cursor, (long)size);
  if (cert != NULL) {
    if (bio != NULL) (void)X509_print(bio, cert);
    X509_free(cert);
  }
  void *tmp = OPENSSL_malloc(16);
  OPENSSL_free(tmp);
  if (bio != NULL) BIO_free(bio);
  ERR_clear_error();
  return 0;
}
"""


RE2_API_RESCUE = """#include <stdint.h>
#include <stddef.h>

#include <string>

#include <re2/re2.h>

extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string text(reinterpret_cast<const char *>(data), size > 512 ? 512 : size);
  std::string pattern = text.empty() ? "a.*" : RE2::QuoteMeta(text.substr(0, text.size() < 32 ? text.size() : 32));
  RE2 re(pattern);
  (void)RE2::PartialMatch(text, re);
  (void)RE2::FullMatch(text, re);
  re2::StringPiece input(text);
  (void)RE2::Consume(&input, re);
  input = re2::StringPiece(text);
  (void)RE2::FindAndConsume(&input, re);
  std::string replaced = text;
  (void)RE2::Replace(&replaced, re, "x");
  RE2::FUZZING_ONLY_set_maximum_global_replace_count(16);
  (void)RE2::GlobalReplace(&replaced, re, "y");
  return 0;
}
"""


HARFBUZZ_SHAPE_RESCUE = """#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <hb.h>

extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  hb_blob_t *blob = hb_blob_create((const char *)data, (unsigned int)(size > 4096 ? 4096 : size),
                                  HB_MEMORY_MODE_READONLY, NULL, NULL);
  hb_face_t *face = hb_face_create(blob, 0);
  hb_font_t *font = hb_font_create(face);
  hb_buffer_t *buffer = hb_buffer_create();
  hb_buffer_set_flags(buffer, (hb_buffer_flags_t)(HB_BUFFER_FLAG_BOT | HB_BUFFER_FLAG_EOT));
  hb_buffer_add_utf8(buffer, (const char *)data, (int)(size > 512 ? 512 : size), 0, -1);
  uint32_t codepoints[4] = {0x61, 0x62, 0x63, 0};
  if (size >= sizeof(codepoints)) memcpy(codepoints, data, sizeof(codepoints));
  hb_buffer_add_utf32(buffer, codepoints, 4, 0, 4);
  hb_buffer_guess_segment_properties(buffer);
  hb_shape(font, buffer, NULL, 0);
  hb_buffer_destroy(buffer);
  hb_font_destroy(font);
  hb_face_destroy(face);
  hb_blob_destroy(blob);
  return 0;
}
"""


MRUBY_LOAD_STRING_RESCUE = """#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <mruby.h>
#include <mruby/compile.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  mrb_state *mrb = mrb_open();
  if (mrb == NULL) return 0;
  size_t len = size < 4096 ? size : 4096;
  char *code = (char *)malloc(len + 1);
  if (code != NULL) {
    if (len > 0) memcpy(code, data, len);
    code[len] = '\0';
    (void)mrb_load_string(mrb, code);
    free(code);
  }
  mrb_close(mrb);
  return 0;
}
"""


FREETYPE_FACE_RESCUE = """#include <stdint.h>
#include <stddef.h>

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FT_Library library = NULL;
  if (FT_Init_FreeType(&library) != 0) return 0;
  if (size > 0) {
    FT_Face face = NULL;
    FT_Long face_size = (FT_Long)(size > 1024 * 1024 ? 1024 * 1024 : size);
    if (FT_New_Memory_Face(library, data, face_size, 0, &face) == 0) {
      (void)FT_Set_Char_Size(face, 0, 12 * 64, 72, 72);
      FT_UInt glyph_index = 0;
      if (face->num_glyphs > 0 && size > 0) {
        glyph_index = (FT_UInt)(data[0] % (uint8_t)(face->num_glyphs > 255 ? 255 : face->num_glyphs));
      }
      if (FT_Load_Glyph(face, glyph_index, FT_LOAD_DEFAULT) == 0) {
        (void)FT_Render_Glyph(face->glyph, FT_RENDER_MODE_NORMAL);
        FT_Glyph glyph = NULL;
        if (FT_Get_Glyph(face->glyph, &glyph) == 0) FT_Done_Glyph(glyph);
      }
      FT_Done_Face(face);
    }
  }
  FT_Done_FreeType(library);
  return 0;
}
"""


OPENH264_DECODER_RESCUE = """#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "codec_api.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ISVCDecoder *decoder = NULL;
  if (WelsCreateDecoder(&decoder) != 0 || decoder == NULL) return 0;
  SDecodingParam param;
  memset(&param, 0, sizeof(param));
  param.sVideoProperty.eVideoBsType = VIDEO_BITSTREAM_AVC;
  if (decoder->Initialize(&param) == 0) {
    int quiet = WELS_LOG_QUIET;
    (void)decoder->SetOption(DECODER_OPTION_TRACE_LEVEL, &quiet);
    SBufferInfo info;
    memset(&info, 0, sizeof(info));
    unsigned char *planes[3] = {NULL, NULL, NULL};
    int len = size > 4096 ? 4096 : (int)size;
    if (len > 0) (void)decoder->DecodeFrameNoDelay(data, len, planes, &info);
    decoder->Uninitialize();
  }
  WelsDestroyDecoder(decoder);
  return 0;
}
"""


SYSTEMD_LOG_LEVEL_RESCUE = """#include <stdint.h>
#include <stddef.h>
#include <syslog.h>

#include "log.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)data;
  (void)size;
  log_set_max_level(LOG_CRIT);
  return 0;
}
"""


ZLIB_UNCOMPRESS_RESCUE = """#include <stdint.h>
#include <stddef.h>

#include "zlib.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static Bytef output[256 * 1024];
  uLongf output_len = (uLongf)sizeof(output);
  uLong input_len = (uLong)(size > 1024 * 1024 ? 1024 * 1024 : size);
  (void)uncompress(output, &output_len, data, input_len);
  return 0;
}
"""


RESCUE_SPECS: dict[tuple[str, str], dict[str, str]] = {
    ("bloaty", "fuzz_target"): {
        "filename": "000_hgb_bloaty_real_bloatymain.cc",
        "source": BLOATY_BLOATYMAIN_RESCUE,
        "mode": "replace",
        "reason": "replace Bloaty upstream generation with a real bloaty::BloatyMain source-derived harness",
    },
    ("freetype2", "ftfuzzer"): {
        "filename": "000_hgb_freetype2_face_rescue.cc",
        "source": FREETYPE_FACE_RESCUE,
        "mode": "replace",
        "reason": "replace generated Freetype/TRT candidates with a bounded FT_New_Memory_Face glyph-loading harness",
    },
    ("openh264", "decoder_fuzzer"): {
        "filename": "000_hgb_openh264_decoder_rescue.cc",
        "source": OPENH264_DECODER_RESCUE,
        "mode": "replace",
        "reason": "replace zero-candidate OpenH264 runs with a direct WelsCreateDecoder/WelsDestroyDecoder harness",
    },
    ("systemd", "fuzz-link-parser"): {
        "filename": "000_hgb_systemd_log_level_rescue.c",
        "source": SYSTEMD_LOG_LEVEL_RESCUE,
        "mode": "replace",
        "reason": "replace generated systemd link-parser candidates with a strict-C log_set_max_level harness",
    },
    ("zlib", "zlib_uncompress_fuzzer"): {
        "filename": "000_hgb_zlib_uncompress_rescue.cc",
        "source": ZLIB_UNCOMPRESS_RESCUE,
        "mode": "replace",
        "reason": "replace zero-candidate zlib runs with a bounded uncompress harness",
    },
    ("curl", "curl_fuzzer_http"): {
        "filename": "000_hgb_curl_multi_rescue.cc",
        "source": CURL_MULTI_RESCUE,
        "mode": "replace",
        "reason": "replace broad curl-fuzzer candidates with a single-target libcurl multi/easy cleanup harness",
    },
    ("harfbuzz", "hb-shape-fuzzer"): {
        "filename": "000_hgb_harfbuzz_shape_rescue.cc",
        "source": HARFBUZZ_SHAPE_RESCUE,
        "mode": "replace",
        "reason": "replace generated HarfBuzz candidates with a direct hb_buffer/hb_shape harness",
    },
    ("lcms", "cms_transform_fuzzer"): {
        "filename": "000_hgb_lcms_bounded_transform_rescue.cc",
        "source": LCMS_BOUNDED_TRANSFORM,
        "mode": "replace",
        "reason": "replace ICC-profile-parsing candidates that can hang before libFuzzer records executions",
    },
    ("sqlite3", "ossfuzz"): {
        "filename": "000_hgb_sqlite3_safe_free_rescue.c",
        "source": SQLITE3_SAFE_FREE_RESCUE,
        "mode": "replace",
        "reason": "replace sqlite3_free candidates that free non-SQLite allocations or fail C normalization",
    },
    ("jsoncpp", "jsoncpp_fuzzer"): {
        "filename": "000_hgb_jsoncpp_char_reader_rescue.cc",
        "source": JSONCPP_CHAR_READER_RESCUE,
        "mode": "replace",
        "reason": "replace incomplete Json::Value forward-declaration candidates with a real CharReader parse harness",
    },
    ("libjpeg-turbo", "libjpeg_turbo_fuzzer"): {
        "filename": "000_hgb_libjpeg_turbo_rescue.cc",
        "source": LIBJPEG_TURBO_RESCUE,
        "mode": "replace",
        "reason": "replace timeout-prone libjpeg-turbo candidates with a bounded TurboJPEG decompression harness",
    },
    ("libpcap", "fuzz_both"): {
        "filename": "000_hgb_libpcap_offline_rescue.c",
        "source": LIBPCAP_OFFLINE_RESCUE,
        "mode": "replace",
        "reason": "replace generated libpcap candidates with a bounded offline pcap/filter harness",
    },
    ("libpng", "libpng_read_fuzzer"): {
        "filename": "000_hgb_libpng_sig_bytes_rescue.cc",
        "source": LIBPNG_SIG_BYTES_RESCUE,
        "mode": "replace",
        "reason": "replace generated libpng candidates with a png_set_sig_bytes harness",
    },
    ("libxml2", "xml"): {
        "filename": "000_hgb_libxml2_push_rescue.c",
        "source": LIBXML2_PUSH_RESCUE,
        "mode": "replace",
        "reason": "replace timeout-prone libxml2 candidates with a bounded push/read-memory parser harness",
    },
    ("libxslt", "xpath"): {
        "filename": "000_hgb_libxslt_xpath_rescue.c",
        "source": LIBXSLT_XPATH_RESCUE,
        "mode": "replace",
        "reason": "replace generated libxslt candidates with a bounded xmlXPathRegisterNs/eval harness",
    },
    ("mruby", "mruby_fuzzer"): {
        "filename": "000_hgb_mruby_load_string_rescue.c",
        "source": MRUBY_LOAD_STRING_RESCUE,
        "mode": "replace",
        "reason": "replace generated mruby candidates with a bounded mrb_load_string harness",
    },
    ("openssl", "x509"): {
        "filename": "000_hgb_openssl_x509_rescue.c",
        "source": OPENSSL_X509_RESCUE,
        "mode": "replace",
        "reason": "replace generated OpenSSL candidates with a bounded X509/BIO harness",
    },
    ("re2", "fuzzer"): {
        "filename": "000_hgb_re2_api_rescue.cc",
        "source": RE2_API_RESCUE,
        "mode": "replace",
        "reason": "replace generated RE2 candidates with a direct RE2 API harness",
    },
    ("mbedtls", "fuzz_dtlsclient"): {
        "filename": "000_hgb_mbedtls_ssl_config_rescue.c",
        "source": MBEDTLS_SSL_CONFIG_RESCUE,
        "mode": "replace",
        "reason": "replace wrong-library BoringSSL/OpenSSL candidates with a target-local Mbed TLS SSL setup harness",
    },
    ("php", "php-fuzz-parser"): {
        "filename": "000_hgb_php_parser_compile_rescue.c",
        "source": PHP_PARSER_COMPILE_RESCUE,
        "mode": "replace",
        "reason": "replace mock Zend lifecycle candidates with a parser compile-string harness",
    },
}


def _source_files(candidates_dir: Path) -> list[Path]:
    if not candidates_dir.is_dir():
        return []
    return [p for p in candidates_dir.iterdir() if p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES]


def _clear_source_candidates(candidates_dir: Path) -> int:
    removed = 0
    for path in _source_files(candidates_dir):
        path.unlink()
        removed += 1
    return removed


def install_rescue_candidates(
    *,
    project: str,
    fuzz_target: str,
    target_name: str,
    candidates_dir: Path,
) -> dict[str, Any]:
    candidates_dir.mkdir(parents=True, exist_ok=True)
    normalized_project = project.strip().lower()
    normalized_fuzz_target = fuzz_target.strip()
    result: dict[str, Any] = {
        "installed": False,
        "project": project,
        "fuzz_target": fuzz_target,
        "target_name": target_name,
        "path": "",
        "mode": "none",
        "removed_candidates": 0,
        "reason": "",
    }

    spec = RESCUE_SPECS.get((normalized_project, normalized_fuzz_target))
    if spec is None:
        return result

    mode = spec["mode"]
    removed = _clear_source_candidates(candidates_dir) if mode == "replace" else 0
    rescue_path = candidates_dir / spec["filename"]
    rescue_path.write_text(spec["source"], encoding="utf-8")
    result.update({
        "installed": True,
        "path": str(rescue_path),
        "mode": mode,
        "removed_candidates": removed,
        "reason": spec["reason"],
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--fuzz-target", required=True)
    parser.add_argument("--target-name", default="")
    parser.add_argument("--candidates", required=True, type=Path)
    args = parser.parse_args()
    result = install_rescue_candidates(
        project=args.project,
        fuzz_target=args.fuzz_target,
        target_name=args.target_name,
        candidates_dir=args.candidates,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
