
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

# 特性

* 继承 [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module) 所有功能.

* 支持基于HTTP协议的FLV播放.

* 支持动态调整GOP缓存个数.

* 支持Socket sharding特性，使 [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module) 在多进程下有更均衡的负载 (必须在 linux kernel 2.6 or later 下运行).

* 提供在 application 更高一层的用户隔离能力 (rtmp service{} block).

* 支持正则匹配 virtual hosts.

* 提供 bkdr hash 进程间哈希级联，减少进程间级联的消耗 (relay_stream hash option).

# 系统支持

* Linux (kernel 2.6 or later are recommended)/FreeBSD/MacOS/Windows (limited).

# 依赖

* GCC for compiling on Unix-like systems.

* MSVC for compiling on Windows (see how to build nginx on win32).

* PCRE, zlib and OpenSSL libraries sources if needed.

# 安装

* 进入 NGINX 源码目录 & 运行以下命令

        ./configure --add-module=/path/to/BLSS
        make
        make install

# 开始使用

* 编译 BLSS 模块.

* 更新 nginx.conf 文件并启动 nginx.

* 推流.

        ffmpeg -re -i live.flv -c copy -f flv rtmp://publish.com[:port]/appname/streamname

* 播放.

        ffplay rtmp://rtmpplay.com[:port]/appname/streamname # RTMP
        ffplay http://flvplay.com[:port]/appname/streamname  # HTTP based FLV
        
# 示例

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
