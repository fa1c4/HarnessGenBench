# PromeFuzz Config Notes

Generated configs are copied from `external/PromeFuzz/config.template.toml` into `results/promefuzz/config_*/config.toml` and patched non-interactively.

No API key is written to the TOML file. `api_key = ""` is preserved so PromeFuzz reads `OPENAI_API_KEY` from the environment at runtime.

```diff
[comprehender]
-embedding_llm = "embedding_llm"
-comprehension_llm = ""
+embedding_llm = "hgb_embedding"
+comprehension_llm = "hgb_cloud"

[generator]
-generation_llm = ""
+generation_llm = "hgb_cloud"

[analyzer]
-analysis_llm = ""
+analysis_llm = "hgb_cloud"

[llm]
-default_llm = "cloud_llm"
+default_llm = "hgb_cloud"

+[llm.hgb_cloud]
+llm_type = "openai"
+base_url = "https://api.openai.com/v1/"
+api_key = ""
+model = "gpt-4o-mini"

+[llm.hgb_embedding]
+llm_type = "openai"
+base_url = "https://api.openai.com/v1/"
+api_key = ""
+model = "text-embedding-3-small"
```
