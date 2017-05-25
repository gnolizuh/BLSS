
# BLSS: Bravo Live Streaming Service 

[![Powered][1]][2] [![Build Status][3]][4] [![Downloads][5]][6]

[1]: https://img.shields.io/badge/nginx--rtmp--module-Powered-blue.svg
[2]: https://github.com/arut/nginx-rtmp-module
[3]: https://travis-ci.org/gnolizuh/BLSS.svg?branch=master
[4]: https://travis-ci.org/gnolizuh/BLSS
[5]: https://img.shields.io/github/downloads/atom/atom/total.svg
[6]: https://github.com/gnolizuh/BLSS/releases

A bravo live streaming service powered by [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module).

## Resources

* [Release Notes](https://github.com/gnolizuh/BLSS/wiki/releasenote)
* [Directives](https://github.com/gnolizuh/BLSS/wiki/directives)

## Features

* RTMP/HTTP+FLV/HLS/MPEG-DASH live streaming

* H264/AAC support, H265 is on the road.

* GOP Cache/HLS VOD features

* Support Socket Sharding feature that to improve load balance (RTMP reuseport)

* Linux/FreeBSD/MacOS/Windows

## Build

cd to NGINX source directory & run this:

    ./configure --add-module=/path/to/BLSS
    make
    make install

## Push/Pull URL format

    rtmp://rtmp.example.com/app/name
    http://flv.example.com/app/name.flv

app -  should match one of application {}
         blocks in config

name - interpreted by each application
         can be empty

## Example(blss.conf)

    # for multi-worker streaming, we support off|hash|all option, default is off.
    worker_processes 8;
    relay_stream hash;

    rtmp {
        log_format bw_in  '[$time_local] pid:$pid sid:$sid slot:$slot bucket:$bucket vhost:$vhost app:$app name:$name remote_addr:$remote_addr proto:$proto rtype:$rtype event:$event bw_in_video_kb:$bw_in_video_kb bw_in_audio_kb:$bw_in_audio_kb bw_in_real_kb:$bw_in_real_kb bw_in_exp_kb:$bw_in_exp_kb bw_in_diff_kb:$bw_in_diff_kb last_audio_ts:$last_audio_ts last_video_ts:$last_video_ts last_av_ts_diff:$last_av_ts_diff audio_ts_min:$audio_ts_min audio_ts_max:$audio_ts_max audio_ts_diff:$audio_ts_diff video_ts_min:$video_ts_min video_ts_max:$video_ts_max video_ts_diff:$video_ts_diff last_video_cts:$last_video_cts bw_in_total_diff_kb:$bw_in_total_diff_kb bw_in_video_exp_kb:$bw_in_video_exp_kb bw_in_audio_exp_kb:$bw_in_audio_exp_kb';
        log_format bw_out '[$time_local] pid:$pid sid:$sid slot:$slot bucket:$bucket vhost:$vhost app:$app name:$name remote_addr:$remote_addr proto:$proto rtype:$rtype event:$event bw_out_kb:$bw_out_kb bw_out_buf_kb:$bw_out_buf_kb last_audio_ts:$last_audio_ts last_video_ts:$last_video_ts last_av_ts_diff:$last_av_ts_diff audio_ts_min:$audio_ts_min audio_ts_max:$audio_ts_max audio_ts_diff:$audio_ts_diff video_ts_min:$video_ts_min video_ts_max:$video_ts_max video_ts_diff:$video_ts_diff';
        access_log /data/logs/blss/rtmp_sla.log bw_in bw_out;
    
        server {

            listen 1935 reuseport;
            
            service cctv {

                hostname pub rtmp httpflv hls *.pubhost.cctv;

                application news {

                    live on;
                    http_flv on;
                    gop_cache on;

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

            service hunantv {

                hostname pub rtmp hls *.pubhost.hunantv;
                hostname sub rtmp hls *.subhost.hunantv;

                application show {

                    live on;
                    http_flv on;
                    gop_cache on;
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
            listen 8080 reuseport;
            listen 80   reuseport;
    
            location / {
                http_flv on;
                hls  on;
    
                root /dev/shm;

                types {
                    application/vnd.apple.mpegurl m3u8;
                    video/mp2t ts;
                }
    
                add_header Access-Control-Allow-Origin *;
            }
        }
    }
