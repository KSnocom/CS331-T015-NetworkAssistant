FROM fedora:44

RUN dnf install -y \
    python3 \
    python3-pip \
    iptables-nft \
    iproute \
    iproute-tc \
    iputils \
    iperf3 \
    procps-ng \
    && dnf clean all

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --no-cache-dir \
       -r /app/requirements.txt

ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY src /app/src
COPY policies /app/policies

RUN mkdir -p /app/logs

CMD ["sleep", "infinity"]
