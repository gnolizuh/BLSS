
# BLSS: Bravo Live Streaming Service 

A bravo live streaming service powered by [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module).

## Status

[![Powered][1]][2] [![Build Status][3]][4] [![Downloads][5]][6]

[1]: https://img.shields.io/badge/nginx--rtmp--module-Powered-blue.svg
[2]: https://github.com/arut/nginx-rtmp-module
[3]: https://travis-ci.org/gnolizuh/BLSS.svg?branch=master
[4]: https://travis-ci.org/gnolizuh/BLSS
[5]: https://img.shields.io/github/downloads/atom/atom/total.svg
[6]: https://github.com/gnolizuh/BLSS/releases

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
cd to BLSS source directory & run this:

    ./configure
    make
    make install

## Example(blss.conf)

    rtmp {
        log_format bw_in  '[$time_local] pid:$pid sid:$sid slot:$slot bucket:$bucket vhost:$vhost app:$app name:$name remote_addr:$remote_addr protocol:$protocol rtype:$rtype event:$event bw_in_video_kb:$bw_in_video_kb bw_in_audio_kb:$bw_in_audio_kb bw_in_real_kb:$bw_in_real_kb bw_in_exp_kb:$bw_in_exp_kb bw_in_diff_kb:$bw_in_diff_kb last_audio_ts:$last_audio_ts last_video_ts:$last_video_ts last_av_ts_diff:$last_av_ts_diff audio_ts_min:$audio_ts_min audio_ts_max:$audio_ts_max audio_ts_diff:$audio_ts_diff video_ts_min:$video_ts_min video_ts_max:$video_ts_max video_ts_diff:$video_ts_diff last_video_cts:$last_video_cts bw_in_total_diff_kb:$bw_in_total_diff_kb bw_in_video_exp_kb:$bw_in_video_exp_kb bw_in_audio_exp_kb:$bw_in_audio_exp_kb';
        log_format bw_out '[$time_local] pid:$pid sid:$sid slot:$slot bucket:$bucket vhost:$vhost app:$app name:$name remote_addr:$remote_addr protocol:$protocol rtype:$rtype event:$event bw_out_kb:$bw_out_kb bw_out_buf_kb:$bw_out_buf_kb last_audio_ts:$last_audio_ts last_video_ts:$last_video_ts last_av_ts_diff:$last_av_ts_diff audio_ts_min:$audio_ts_min audio_ts_max:$audio_ts_max audio_ts_diff:$audio_ts_diff video_ts_min:$video_ts_min video_ts_max:$video_ts_max video_ts_diff:$video_ts_diff';
        access_log /data/logs/blss/rtmp_sla.log bw_in bw_out;
    
        server {

            listen 1935 reuseport;

            bucket blss {

                pubhost {
                    rtmp blss.rtmppub.live.cn;
                }

                subhost {
                    rtmp blss.rtmpsub.live.cn;
                    flv blss.flvsub.live.cn;
                    hls blss.hlssub.live.cn;
                }

                application news {

                    http_flv on;
                    hls on;
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
