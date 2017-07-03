
# BLSS: Bravo Live Streaming Service 

[![Powered][1]][2] [![Build Status][3]][4] [![Downloads][5]][6]

[1]: https://img.shields.io/badge/nginx--rtmp--module-Powered-blue.svg
[2]: https://github.com/arut/nginx-rtmp-module
[3]: https://travis-ci.org/gnolizuh/BLSS.svg?branch=master
[4]: https://travis-ci.org/gnolizuh/BLSS
[5]: https://img.shields.io/github/downloads/atom/atom/total.svg
[6]: https://github.com/gnolizuh/BLSS/releases

## 简介

BLSS是在NGINX框架下实现的一个第三方模块，它在[nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module)基础上二次开发实现，在保留原有特性的基础上，
新增部分功能：HTTP-FLV协议的分发、GOP缓存、正则匹配推拉流域名、vhost概念、灵活的日志输出等，使用BLSS可以轻松的完成一个大规模分布式流媒体集群的搭建。

## 安装依赖

- [nginx](https://nginx.org/)

## 安装方法

下载[nginx](https://nginx.org/)源码并解压：

    wget https://nginx.org/download/nginx-$VERSION.tar.gz
    tar zxvf nginx-$VERSION.tar.gz

下载[BLSS](https://github.com/gnolizuh/BLSS/releases)源码并解压：

    wget https://github.com/gnolizuh/BLSS/archive/v1.1.4.tar.gz
    tar zxvf v1.1.4.tar.gz

编译[BLSS](https://github.com/gnolizuh/BLSS/releases)：

    cd NGINX-SRC-DIR
    ./configure --add-module=/path/to/BLSS
    make
    make install

编译DEBUG模式(输出DEBUG日志)：

    ./configure --add-module=/path/to/BLSS --with-debug

## 配置步骤

修改配置文件如下：

    worker_processes 8;   # 开启多进程模式
    relay_stream hash;    # 选择多进程级联工作模式

    rtmp {
        server {
            listen 1935 reuseport;    # 惊群模式

            service cctv {
                hostname pub rtmp *.pub.rtmp.cctv;         # 正则匹配RTMP推流域名
                hostname sub rtmp *.sub.rtmp.cctv;         # 正则匹配RTMP拉流域名
                hostname sub http_flv *.sub.httpflv.cctv;  # 正则匹配HTTP-FLVP拉流域名

                application news {
                    live on;
                    http_flv on;
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
                http_flv on;
            }
        }
    }

启动nginx

    ./obj/nginx -p /path/to/nginx

## 测试

### 测试工具

- [OBS](https://obsproject.com/) [**推流**]
- [FFMPEG](https://ffmpeg.org/) [**推流/播放**]
- [VLC](http://www.videolan.org/vlc/) [**播放**]

### 测试方法

#### 推流

客户端绑定host，192.168.1.100为nginx服务器IP：

    192.168.1.100 test.pub.rtmp.cctv  # RTMP推流地址
    192.168.1.100 test.sub.rtmp.cctv  # RTMP播放地址
    192.168.1.100 test.sub.httpflv.cctv  # HTTP-FLV播放地址

下面以FFMPEG进行RTMP推流，绑定test.pub.rtmp.cctv为nginx服务器IP，然后推流：

    ffmpeg -re -i movie.flv -vcodec copy -a codec copy -f flv rtmp://test.pub.rtmp.cctv/live/test

播放RTMP地址：

    rtmp://test.sub.rtmp.cctv/live/test

播放HTTP-FLV地址

    http://test.sub.httpflv.cctv/live/test.flv
