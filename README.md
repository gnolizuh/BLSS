
BLSS: Bravo Live Streaming Service 
======================================

[![Powered][1]][2] [![Build Status][3]][4] [![Downloads][5]][6]

[1]: https://img.shields.io/badge/nginx--rtmp--module-Powered-blue.svg
[2]: https://github.com/arut/nginx-rtmp-module
[3]: https://travis-ci.org/gnolizuh/BLSS.svg?branch=master
[4]: https://travis-ci.org/gnolizuh/BLSS
[5]: https://img.shields.io/github/downloads/atom/atom/total.svg
[6]: https://github.com/gnolizuh/BLSS/releases

[中文说明](https://github.com/gnolizuh/BLSS/blob/master/README.zh.md) 

# Introduction

BLSS is a NGINX third-party module, which is based on the secondary development of open source projects [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module) to achieve, based on the original features to retain some of the key features,
Such as HTTP-FLV protocol distribution, GOP cache, regular match push-pull domain name, virtual host and so on.

# Installation

Download [nginx](https://nginx.org/)：

    wget https://nginx.org/download/nginx-$VERSION.tar.gz
    tar zxvf nginx-$VERSION.tar.gz

Download [BLSS](https://github.com/gnolizuh/BLSS/releases)：

    wget https://github.com/gnolizuh/BLSS/archive/v1.1.4.tar.gz
    tar zxvf v1.1.4.tar.gz

Compile and install：

    cd NGINX-SRC-DIR
    ./configure --add-module=/path/to/BLSS
    make
    make install

Compile with debug mode：

    ./configure --add-module=/path/to/BLSS --with-debug

# Configuration

A nginx.conf example：

    worker_processes 8;   # multi-worker process mode
    relay_stream hash;    # stream relay mode

    # rtmp block
    rtmp {
        server {
            listen 1935 reuseport;

            service cctv {
                hostname pub rtmp *.pub.rtmp.cctv;         # match rtmp push domain
                hostname sub rtmp *.sub.rtmp.cctv;         # match rtmp pull domain
                hostname sub http_flv *.sub.httpflv.cctv;  # match http-flv pull domain

                application news {
                    live on;
                    gop_cache on;
                    gop_cache_count 5;  # cache 5 GOPs

                    hls on;
                    hls_fragment 10s;
                    hls_playlist_length 30s;
                }

                application sports {
                    hls on;
                    hls_fragment 1m;
                    hls_playlist_length 3m;
                }
            }
        }
    }
    
    http {
        include      mime.types;
        default_type application/octet-stream;

        log_format   main  '$remote_addr - $remote_user [$time_local] "$request" '
                            '$status $body_bytes_sent "$http_referer" '
                            '"$http_user_agent" "$http_x_forwarded_for"';

        access_log   logs/http_sla.log main;

        keepalive_timeout 60;

        server {
            listen 80 reuseport;

            location / {
                http_flv on;    # delivery http-flv
            }
        }
    }

run nginx:

    ./obj/nginx -p /path/to/nginx
