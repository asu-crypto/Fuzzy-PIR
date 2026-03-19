#!/bin/bash

sudo docker run -d --rm \
    -v $(pwd)/src:/home/ubuntu/src \
    --cap-add=NET_ADMIN \
    fuzzy-pir:latest \
    tail -f /dev/null
