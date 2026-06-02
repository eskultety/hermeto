FROM mirror.gcr.io/library/rust:1-alpine

# Test disabled network access
RUN if getent hosts www.google.com; then echo "Has network access!"; exit 1; fi

WORKDIR /src
RUN . /tmp/cachi2.env && cargo build --offline
