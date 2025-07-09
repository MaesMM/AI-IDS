apt -o "Acquire::https::Verify-Peer=false" update && apt -o "Acquire::https::Verify-Peer=false" install ca-certificates -y && \
    update-ca-certificates && \
    apt -o "Acquire::https::Verify-Peer=false" install -y \
    iproute2 \
    tzdata \
    python3 \
    python3-venv \
    python3-pip \
    build-essential \
    cmake \
    g++ \
    flex \
    bison \
    libcap2 \
    libpcre2-dev \
    libdnet-dev \
    libdumbnet-dev \
    libluajit-5.1-dev \
    libtins-dev \
    libhwloc-dev \
    zlib1g-dev \
    pkg-config \
    libssl-dev \
    git \
    wget \
    liblzma-dev \
    libnghttp2-dev \
    uuid-dev \
    libmnl-dev \
    nano \
    vim \
    iputils-ping \
    curl \
    tcpdump \
    bash \
    libreadline-dev \
    libncurses-dev \
    net-tools\
    && rm -rf /var/lib/apt/lists/*