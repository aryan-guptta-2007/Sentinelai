# A real systemd host in a container, for tests/linux/systemd_check.sh.
# Needs --privileged, because it runs its own init and network namespaces.
FROM debian:12

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server openssh-client sshpass python3 python3-venv \
      passwd procps iproute2 nftables curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd

COPY . /src
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
