## Source : ettorecalvi: snortml2docker;
# Start from a base image, like Ubuntu 20.04
FROM ubuntu:25.10

# Set environment variable to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update packages and install all necessary dependencies
RUN apt -o "Acquire::https::Verify-Peer=false" update && apt -o "Acquire::https::Verify-Peer=false" install ca-certificates -y && \
    update-ca-certificates && \
    apt -o "Acquire::https::Verify-Peer=false" install -y \
    python3 \
    python3-venv \
    python3-pip \
    pipx \
    # seclist \
    git \
    wget \
    nano \
    vim \
    iputils-ping \
    curl \
    tcpdump \
    dnsutils \
    nmap \
    arjun \
    # dalfox \
    dnsenum \
    sqlmap \
    wafw00f \
    && rm -rf /var/lib/apt/lists/*


# Set the working directory
WORKDIR /usr/local

# Add pipx to PATH variable
# RUN pipx ensurepath
ENV PATH "$PATH:/root/.local/bin"

ENV PATH "$PATH:/usr/local/go/bin"
# Download and install Go
RUN wget https://go.dev/dl/go1.24.3.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.24.3.linux-amd64.tar.gz && \
    go version

# Download and install assetfinder
# Find domains and subdomains potentially related to a given domain
RUN wget https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz && \
    tar -xf assetfinder-linux-amd64-0.1.1.tgz && \
    mv assetfinder /bin/assetfinder

# Download and install nuclei
# Vulnerability scanner
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Download and install Arjun
# Find query parameters for URL endpoints
# RUN pipx install arjun


# Download and install AutoRecon
RUN pipx install git+https://github.com/Tib3rius/AutoRecon.git

# Download and install dalfox
# XSS scanner
RUN go install github.com/hahwul/dalfox/v2@latest

CMD ["/bin/bash"]
