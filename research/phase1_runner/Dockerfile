# GhostStrike Phase 1 evaluation runner.
#
# GhostStrike's bash_scripts_for_pentest modules assume a Linux host with
# real pentest tooling installed (nmap, nikto, etc.) -- neither exists on
# the Windows machine this research was authored on. This container
# provides that real Linux environment, joined to the existing
# pentest_lab_pentest_network so it can reach the already-running lab
# targets (DVWA, Juice Shop, NodeGoat, WebGoat, WordPress, SSH/FTP/Telnet,
# vulnerable_services) exactly the way an operator's own Kali box would.
#
# Not part of the shipped product -- lives under research/, used only to
# generate the Phase 1 evaluation data for the paper.
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap nikto python3 python3-pip python3-venv git curl ca-certificates \
    ftp telnet openssh-client jq sudo \
    && rm -rf /var/lib/apt/lists/*

# nuclei isn't in the default Kali metapackage set pulled above; install
# the official static binary directly rather than relying on a
# potentially-stale apt package.
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip \
    -o /tmp/nuclei.zip \
    && (unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei 2>/dev/null || (apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/* && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei)) \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip

# The GhostStrike repo itself is bind-mounted at container run time
# (-v .../GhostStrike:/opt/ghoststrike), not COPYed at build time --
# the repo's working tree has hundreds of timestamped module-output
# directories from local testing that have no business inside a built
# image, and a mount also means edits on the host are immediately visible
# without a rebuild.
WORKDIR /opt/ghoststrike

RUN pip3 install --break-system-packages --no-cache-dir \
    requests jsonschema PyYAML rich cryptography markdown python-docx fpdf2 anthropic openai \
    2>/dev/null || true

CMD ["/bin/bash"]