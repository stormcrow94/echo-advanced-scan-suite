# Use a recent Ubuntu image as the base
FROM ubuntu:22.04

# Set the working directory
WORKDIR /app

# Install system dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y \
    git \
    wget \
    curl \
    jq \
    nmap \
    libpcap-dev \
    build-essential \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget -q https://go.dev/dl/go1.23.4.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz && \
    rm go1.23.4.linux-amd64.tar.gz

# Set up the PATH for Go
ENV PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"
ENV GOPATH="/opt/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Install Go tools to /opt/go/bin
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/tomnomnom/assetfinder@latest
RUN go install -v github.com/owasp-amass/amass/v4/...@latest
RUN go install -v github.com/tomnomnom/anew@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/003random/getJS@latest
RUN go install -v github.com/tomnomnom/waybackurls@latest

# Install findomain
RUN wget -q https://github.com/Findomain/Findomain/releases/download/10.0.1/findomain-linux.zip && \
    unzip findomain-linux.zip && \
    mv findomain /usr/local/bin/ && \
    rm findomain-linux.zip

# Make Go binaries accessible to all users
RUN chmod -R 755 /opt/go

# Copy the recon script into the container
COPY recon.sh .

# Make the script executable
RUN chmod +x recon.sh

# Create a non-privileged user
RUN useradd -m -u 1000 recon && \
    chown -R recon:recon /app

# Switch to non-privileged user
USER recon

# Set the entrypoint
ENTRYPOINT ["/app/recon.sh"]
