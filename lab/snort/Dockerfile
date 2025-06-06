## Source : ettorecalvi: snortml2docker;
# Start from a base image, like Ubuntu 20.04
FROM ubuntu:20.04


# Set environment variable to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
# ENV PKGCONFIG_PATH=/usr/lib/pkgconfig:/usr/lib32/pkgconfig:/usr/local/lib/pkgconfig:/usr/local/lib32/pkgconfig

# RUN echo -e "// Do not verify peer certificate\nAcquire::https::Verify-Peer \"false\";\n// Do not verify that certificate name matches server name\nAcquire::https::Verify-Host \"false\";"  > /etc/apt/apt.conf.d/

# Update packages and install all necessary dependencies
RUN apt -o "Acquire::https::Verify-Peer=false" update && apt -o "Acquire::https::Verify-Peer=false" install ca-certificates -y && \
    update-ca-certificates && \
    apt -o "Acquire::https::Verify-Peer=false" install -y \
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

# Set the working directory
WORKDIR /usr/local

# Download and install libdaq
RUN git clone https://github.com/snort3/libdaq.git /tmp/libdaq && \
    cd /tmp/libdaq && \
    ./bootstrap && \
    ./configure --prefix=/usr/local/lib/daq_s3 && \
    make && \
    make install && \
    rm -rf /tmp/libdaq

# Add libdaq library path to the dynamic linker
RUN echo "/usr/local/lib/daq_s3/lib" | tee /etc/ld.so.conf.d/daq.conf && ldconfig
RUN export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib/daq_s3/lib/pkgconfig

# Download and install libml
RUN git clone https://github.com/snort3/libml.git /tmp/libml && \
    cd /tmp/libml && \
    ./configure.sh --prefix=/usr/local/libml && \
    cd build && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/libml 

# Reclone libml to get the examples    
RUN mkdir -p /usr/local/src/libml && \
chmod 755 /usr/local/src/libml && \
git clone https://github.com/snort3/libml.git /usr/local/src/libml


# Add libml library path to the dynamic linker
RUN echo "/usr/local/libml/lib" | tee /etc/ld.so.conf.d/libml.conf && ldconfig

# Download and install Snort3 with libml support
RUN git clone https://github.com/snort3/snort3.git /tmp/snort3 && \
    cd /tmp/snort3 && \
    ./configure_cmake.sh --prefix=/usr/local/snort \
                         --with-daq-includes=/usr/local/lib/daq_s3/include/ \
                         --with-daq-libraries=/usr/local/lib/daq_s3/lib/ \
                         --with-dnet-includes=/usr/include \
                         --with-dnet-libraries=/usr/lib \
                         --with-libml-includes=/usr/local/libml/include \
                         --with-libml-libraries=/usr/local/libml/lib \
                         --enable-debug-msgs && \
    cd build && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/snort3

# Create an alias for Snort including the DAQ directory path
RUN echo "alias snort='/usr/local/snort/bin/snort --daq-dir /usr/local/lib/daq_s3/lib/daq'" >> /root/.bashrc

# Copy custom rules and scripts
COPY local.rules /usr/local/snort/etc/snort/
COPY pcapgen.py /usr/local/src/libml/examples/classifier/pcapgen.py
RUN rm /usr/local/snort/etc/snort/snort.lua
COPY config.lua /usr/local/snort/etc/snort/snort.lua
RUN pwd
COPY entrypoint.sh . 
RUN chmod +x /usr/local/entrypoint.sh
CMD ["/usr/local/entrypoint.sh"]
