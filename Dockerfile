# Build stage
FROM alpine:3.21 AS builder

# Install tools to extract the bundled Zig toolchain
RUN apk add --no-cache tar xz

WORKDIR /opt
COPY zig-x86_64-linux-0.16.0.tar.xz /opt/zig.tar.xz
RUN tar -xf zig.tar.xz && \
    mv zig-x86_64-linux-0.16.0 /opt/zig && \
    rm zig.tar.xz

ENV PATH="/opt/zig:${PATH}"

WORKDIR /app
COPY build.zig build.zig.zon ./
COPY src/ ./src/

# Build the executable
RUN zig build -Doptimize=ReleaseFast

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/zig-out/bin/zig-link ./
COPY --from=builder /app/src/index.html ./src/
COPY --from=builder /app/src/a.png ./src/

# Create data directory
RUN mkdir -p data

EXPOSE 8080

ENTRYPOINT ["./zig-link"]
CMD ["8080"]