#!/bin/bash
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl

# Docker's official apt repo ships docker-ce, the compose plugin, and the
# buildx plugin together, matched to the box's architecture automatically.
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable --now docker
usermod -aG docker ubuntu

mkdir -p /opt/lab/app /opt/lab/db
cd /opt/lab

# Files are passed in base64 (not raw heredocs) so none of the app/SQL
# source's quotes, backticks, or `$` characters can interact with either
# bash or Terraform's own template interpolation.
echo '${app_py_b64}' | base64 -d > app/app.py
echo '${app_requirements_b64}' | base64 -d > app/requirements.txt
echo '${app_dockerfile_b64}' | base64 -d > app/Dockerfile
echo '${db_dockerfile_b64}' | base64 -d > db/Dockerfile
echo '${db_init_sql_b64}' | base64 -d > db/init.sql
echo '${docker_compose_b64}' | base64 -d > docker-compose.yml

docker compose up -d --build
