#!/bin/bash
set -exv
docker build  --no-cache \
              --force-rm \
              -t rhel-fabric8-analytics-f8a-server-backbone:latest  \
              -f ./Dockerfile.rhel .
