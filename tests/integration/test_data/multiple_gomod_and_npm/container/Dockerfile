FROM registry.access.redhat.com/ubi9/ubi@sha256:80b1f4c34a7eed1b03a05d12b55768f3e522eef6ec294c6fbd5fa47b6b2892ee

# Test disabled network access
RUN if getent hosts www.google.com; then echo "Has network access!"; exit 1; fi

# Install dependencies from RPM lockfile
RUN dnf -y install golang npm

WORKDIR /src/gomod-package
RUN . /tmp/hermeto.env && go build

WORKDIR /src/npm-package
RUN . /tmp/hermeto.env && npm install
