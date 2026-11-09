# Static nandi binary on an empty base image.
#
#   docker build -t nandi .
#   docker run --rm -p 8787:8787 -p 8788:8788 -v "$PWD:/etc/nandi" nandi
#
# The mounted nandi.yaml must bind 0.0.0.0 (listen.proxy, admin.listen), set
# admin.token, and point data_dir at a writable path such as /var/lib/nandi.

FROM rust:alpine AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p nandi \
 && mkdir -p /out/var/lib/nandi /out/etc/nandi \
 && cp target/release/nandi /out/nandi \
 && chown -R 65532:65532 /out/var/lib/nandi

FROM scratch
COPY --from=build /out/nandi /usr/local/bin/nandi
COPY --from=build /out/var/lib/nandi /var/lib/nandi
COPY --from=build /out/etc/nandi /etc/nandi
USER 65532:65532
ENV NANDI_CONFIG=/etc/nandi/nandi.yaml
EXPOSE 8787 8788
VOLUME ["/var/lib/nandi"]
ENTRYPOINT ["nandi"]
CMD ["run", "-c", "/etc/nandi/nandi.yaml"]
