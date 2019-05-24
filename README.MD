# Proof of concept of NGINX + JWT Validation

This is a proof of concept of JWT token validation with NGINX using NJS, a subset of Javascript that
allows extending NGINX functionalities: https://nginx.org/en/docs/njs/  
We will try to consume a protected static file, that will be accessible only when a valid token is provided.

Please note:   
NGINX can already validate JWT Tokens, but only with the Plus subscription

https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-jwt-authentication/

https://www.nginx.com/products/buy-nginx-plus/

## Project startup

    git clone
    bash pull.sh
    bash start.sh
    
The container will start and attach to port 81.
    
You must have a valid JWT token, for example the following one

    http://localhost:81/private/private_file.txt?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o
    
will return `private file`

but using a wrong token

    http://localhost:81/private/private_file.txt?token=xxx

will return an error.

Moreover, a static test file with no JWT validation is provided at 

    http://localhost:81/static/static_file.txt

The secret used to validate this token is "secret" (look in `config\module.js`)

## Stop

    bash stop.sh

## Benchmark

A benchmark to measure the overhead of this kind of validation is provided here: https://github.com/lombax85/nginx-njs-benchmark

## Credits
- The token validation has been done with a slightly modified version of https://github.com/hokaccha/node-jwt-simple
 