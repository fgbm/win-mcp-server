FROM python:3.11-slim

RUN pip install --no-cache-dir \
    "fastmcp==4.0.5" \
    "pywinrm==0.5.0"

COPY app.py /app/app.py
COPY agent  /app/agent

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /app/logs

# Inside the container all interfaces are fine — reachability is decided by
# how the port is published. The code defaults to 127.0.0.1 for runs on a
# host, where that default is what keeps the port off the network.
ENV MCP_BIND_HOST=0.0.0.0

WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]
