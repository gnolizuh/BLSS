
BLSS: Bravo Live Streaming Service 
======================================

[![Powered][1]][2] [![Build Status][3]][4] [![Downloads][5]][6]

[1]: https://img.shields.io/badge/nginx--rtmp--module-Powered-blue.svg
[2]: https://github.com/arut/nginx-rtmp-module
[3]: https://travis-ci.org/gnolizuh/BLSS.svg?branch=master
[4]: https://travis-ci.org/gnolizuh/BLSS
[5]: https://img.shields.io/github/downloads/atom/atom/total.svg
[6]: https://github.com/gnolizuh/BLSS/releases

Media streaming server based on [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module).

# Features

* All features of [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module) are inherited, i.e., it is 100% compatible with [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module).

* HTTP-based FLV live streaming support.

* Dynamic GOP cache for low latency.

* Socket sharding feature for higer performance (MUST be linux kernel 2.6 or later).

* Ability to separate different users at top of application block (rtmp service{} block).

* Dynamic matching virtual hosts supported.

* Provide ability for relaying by bkdr hash function (relay_stream hash option).

# Systems supported

* Linux (kernel 2.6 or later are recommended)/FreeBSD/MacOS/Windows (limited).

# Dependencies

* [GCC](https://gcc.gnu.org/) for compiling on Unix-like systems.

* [MSVC](http://www.mingw.org/wiki/MSYS) for compiling on Windows (see [how to build nginx on win32](http://nginx.org/en/docs/howto_build_on_win32.html)).

* [PCRE](http://www.pcre.org/), [zlib](http://zlib.net/) and [OpenSSL](http://www.openssl.org/) libraries sources if needed.

# Build

cd to NGINX source directory & run this:

    ./configure --add-module=/path/to/BLSS
    make
    make install

# Get Started 

* Build BLSS module according to the section above.

* Configure the nginx.conf file and start nginx.

* Publish stream.

        ffmpeg -re -i live.flv -c copy -f flv rtmp://publish.com[:port]/appname/streamname

* Play.

        ffplay rtmp://rtmpplay.com[:port]/appname/streamname # RTMP
        ffplay http://flvplay.com[:port]/appname/streamname  # HTTP based FLV

# Example

    worker_processes 8;   # multi-worker process mode
    relay_stream hash;    # stream relay mode

    rtmp {
        server {
            listen 1935 reuseport;

            service cctv {
                hostname pub rtmp publish.com;      # match rtmp push domain
                hostname sub rtmp rtmpplay.com;     # match rtmp pull domain
                hostname sub http_flv flvplay.com;  # match http-flv pull domain

                application live {
                    live on;
                    gop_cache on;
                    gop_cache_count 5;  # cache 5 GOPs

                    hls on;
                    hls_fragment 10s;
                    hls_playlist_length 30s;
                }
            }
        }
    }

# Groups

![Alt text](groups.png "wechat QR code")
