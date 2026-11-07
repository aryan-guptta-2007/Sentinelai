# Runs the Linux-only checks: real collectors, real attacks, real nftables and usermod.
# Needs NET_ADMIN for the firewall and SYS_PTRACE, which Docker removes and a real root
# has, to see which process owns a socket belonging to another account.
FROM python:3.11-slim
WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 procps nftables iptables netcat-openbsd shellcheck passwd \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
CMD ["bash", "tests/linux/run.sh"]
