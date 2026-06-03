# A corresponding rpms.lock.yaml was built for UBI9
FROM registry.access.redhat.com/ubi9/ubi@sha256:80b1f4c34a7eed1b03a05d12b55768f3e522eef6ec294c6fbd5fa47b6b2892ee

# Test disabled network access
RUN if getent hosts www.google.com; then echo "Has network access!"; exit 1; fi

# These packages must be prefetched during the previous phase.
# Refer to the test for further details.
RUN dnf -y install \
    cargo \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    python3-devel \
    libffi-devel \
    openssl-devel

WORKDIR /src

RUN . /tmp/hermeto.env \
    && python3 -m pip install -r requirements.txt

# See pip/e2e for the resasoning behind switching WORKDIR
RUN cp -r /src /app
WORKDIR /app
