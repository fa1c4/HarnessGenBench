# Local Embedding Models

This directory is for local embedding model weights used by strict CKGFuzzer
reproduction runs. Model weights are downloaded on the local machine and must
not be committed to git.

The default model path is:

```text
models/Qwen3-Embedding-0.6B
```

Use `scripts/download_embedding_model.py` to download the Hugging Face snapshot,
then use `scripts/local_embedding_server.sh` to serve it with the Hugging Face
Text Embeddings Inference CPU Docker image. CKGFuzzer calls that service through
an OpenAI-compatible `/v1/embeddings` endpoint.
