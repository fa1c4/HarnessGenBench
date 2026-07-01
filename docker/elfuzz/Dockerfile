FROM ghcr.io/osuseclab/elfuzz:25.08.0
COPY artifacts/elfuzz /opt/hgb/artifacts/elfuzz
COPY docker/elfuzz/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
