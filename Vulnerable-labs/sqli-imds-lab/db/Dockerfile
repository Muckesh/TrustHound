# Postgres image with the pgsql-http extension built in.
#
# pgsql-http (https://github.com/pramsey/pgsql-http) adds SQL functions
# (http_get, http_post, http(), ...) that let a query itself perform an
# outbound HTTP request via libcurl and return the response body as a
# SQL value. That's the mechanism this lab uses to turn a plain SQL
# injection into an SSRF against 169.254.169.254 without any app-level
# "fetch this URL" feature — the database engine does the fetching.
FROM postgres:16

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       postgresql-server-dev-16 \
       libcurl4-openssl-dev \
       git \
       ca-certificates \
    && git clone --depth 1 https://github.com/pramsey/pgsql-http.git /tmp/pgsql-http \
    && cd /tmp/pgsql-http \
    && make \
    && make install \
    && cd / \
    && rm -rf /tmp/pgsql-http \
    && apt-get purge -y --auto-remove build-essential postgresql-server-dev-16 git \
    && rm -rf /var/lib/apt/lists/*

COPY init.sql /docker-entrypoint-initdb.d/01-init.sql
