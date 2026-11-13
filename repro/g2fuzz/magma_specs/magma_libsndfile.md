# G2Fuzz MAGMA target: `libsndfile`

- MAGMA target: `libsndfile`, program `sndfile_fuzzer`
- Format: audio containers (WAV, AIFF, AU, MP3, CAF)
- Paper alignment: upstream G2Fuzz maps `sndfile_fuzzer` to
  `raw, wav, au, aiff, aifc, mp3, caf`; paper-faithful binary-format cell.
- Generator focus: RIFF/WAVE chunks (fmt, data, LIST, fact, cue, smpl),
  AIFF/AIFC COMM/SSND, AU headers, CAF chunks, valid sample rates, channel
  counts, bit depths, and compressed payload descriptors.
