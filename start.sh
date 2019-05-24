#!/bin/bash
docker run --name test-nginx-container \
        -v $(pwd)/config/nginx.conf:/etc/nginx/nginx.conf:ro \
        -v $(pwd)/config/module.js:/etc/nginx/module.js:ro \
        -v $(pwd)/html:/usr/share/nginx/html \
        -p 81:81 -d nginx
