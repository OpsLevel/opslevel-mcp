FROM ubuntu:noble AS release
ENV USER_UID=1001 USER_NAME=opslevel
ENTRYPOINT ["/usr/local/bin/opslevel-mcp"]
WORKDIR /app
RUN apt-get update && \
    apt-get install -y ca-certificates jq && \
    apt-get purge && apt-get clean && apt-get autoclean
COPY opslevel-mcp /usr/local/bin