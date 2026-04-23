FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential gcc g++ make cmake \
    git curl wget \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ARG REPO_URL
ARG COMMIT_SHA

WORKDIR /src
RUN git clone ${REPO_URL} app && \
    cd app && \
    git checkout ${COMMIT_SHA}

WORKDIR /src/app
RUN make 2>/dev/null || cmake . && make 2>/dev/null || gcc -o app *.c 2>/dev/null || true

CMD ["/bin/bash"]
