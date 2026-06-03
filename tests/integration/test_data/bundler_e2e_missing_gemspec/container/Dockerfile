FROM mirror.gcr.io/library/ruby:4.0.5

# Test disabled network access
RUN if getent hosts www.google.com; then echo "Has network access!"; exit 1; fi

WORKDIR /src

RUN . /tmp/hermeto.env && bundle install
