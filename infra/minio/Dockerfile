# Static MinIO binary built by infra/build_minio.sh from the official source.
FROM scratch
COPY minio /minio
EXPOSE 9000 9001
ENTRYPOINT ["/minio"]
