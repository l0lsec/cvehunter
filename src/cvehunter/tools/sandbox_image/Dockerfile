FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    requests==2.32.3 ldap3==2.9.1 dnslib==0.9.25 \
    pwntools==4.13.0 cryptography==43.0.1 pyjwt==2.9.0 \
    paramiko==3.5.0 pycryptodome==3.21.0
