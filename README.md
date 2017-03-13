

# BLSS: Bravo Live Streaming Service 

A bravo live streaming service powered by [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module).

## Resources

* [Release Notes](https://github.com/gnolizuh/BLSS/wiki/releasenote)
* [Directives](https://github.com/gnolizuh/BLSS/wiki/directives)

## Features

* RTMP/HTTP+FLV/HLS/MPEG-DASH live streaming

* H264/H265/AAC support

* Linux/FreeBSD/MacOS/Windows

## Build
cd to BLSS source directory & run this:

    ./configure
    make
    make install

## Example(blss.conf)

    rtmp {
        log_format bw_in        '[$time_local] cid:$cid lid:$lid pid:$pid sid:$sid slot:$slot unique_name:$unique_name vhost:$vhost app:$app name:$name remote_addr:$remote_addr protocol:$protocol rtype:$rtype event:$event bw_in_video_kb:$bw_in_video_kb bw_in_audio_kb:$bw_in_audio_kb bw_in_real_kb:$bw_in_real_kb bw_in_exp_kb:$bw_in_exp_kb bw_in_diff_kb:$bw_in_diff_kb last_audio_ts:$last_audio_ts last_video_ts:$last_video_ts last_av_ts_diff:$last_av_ts_diff audio_ts_min:$audio_ts_min audio_ts_max:$audio_ts_max audio_ts_diff:$audio_ts_diff video_ts_min:$video_ts_min video_ts_max:$video_ts_max video_ts_diff:$video_ts_diff last_video_cts:$last_video_cts bw_in_total_diff_kb:$bw_in_total_diff_kb bw_in_video_exp_kb:$bw_in_video_exp_kb bw_in_audio_exp_kb:$bw_in_audio_exp_kb';
        log_format bw_out       '[$time_local] cid:$cid lid:$lid pid:$pid sid:$sid slot:$slot unique_name:$unique_name vhost:$vhost app:$app name:$name remote_addr:$remote_addr protocol:$protocol rtype:$rtype event:$event bw_out_kb:$bw_out_kb bw_out_buf_kb:$bw_out_buf_kb last_audio_ts:$last_audio_ts last_video_ts:$last_video_ts last_av_ts_diff:$last_av_ts_diff audio_ts_min:$audio_ts_min audio_ts_max:$audio_ts_max audio_ts_diff:$audio_ts_diff video_ts_min:$video_ts_min video_ts_max:$video_ts_max video_ts_diff:$video_ts_diff';
        log_format evt_in       '[$time_local] cid:$cid lid:$lid pid:$pid sid:$sid slot:$slot unique_name:$unique_name vhost:$vhost app:$app name:$name remote_addr:$remote_addr protocol:$protocol rtype:$rtype event:$event rtmp_stage:$rtmp_stage$rtmp_args';
        log_format evt_rtmp_out '[$time_local] cid:$cid lid:$lid pid:$pid sid:$sid slot:$slot unique_name:$unique_name vhost:$vhost app:$app name:$name remote_addr:$remote_addr protocol:$protocol rtype:$rtype event:$event rtmp_stage:$rtmp_stage$rtmp_args';
        log_format evt_hls_out  '[$time_local] cid:$cid lid:$lid pid:$pid sid:$sid slot:$slot unique_name:$unique_name vhost:$vhost app:$app name:$name remote_addr:$remote_addr protocol:$protocol rtype:$rtype event:$event status_code:$status_code hls_name:$hls_name hls_stime_ms:$hls_stime_ms hls_etime_ms:$hls_etime_ms hls_diff_ms:$hls_diff_ms';
        log_format evt_hdl_out  '[$time_local] cid:$cid lid:$lid pid:$pid sid:$sid slot:$slot unique_name:$unique_name vhost:$vhost app:$app name:$name remote_addr:$remote_addr protocol:$protocol rtype:$rtype event:$event status_code:$status_code';
        access_log /data/logs/blss/rtmp_sla.log bw_in bw_out evt_in evt_rtmp_out evt_hls_out evt_hdl_out;
    
        include                includes/depend/vars.conf;
        
        on_connect             unix:/dev/shm/rtmp.sock:/connect;
        on_publish             unix:/dev/shm/rtmp.sock:/publish;
        on_play                unix:/dev/shm/rtmp.sock:/play;
        on_update              unix:/dev/shm/rtmp.sock:/update;
        on_publish_done        unix:/dev/shm/rtmp.sock:/publish_done;

        server {
            listen 1935 so_keepalive=1:2:3 reuseport;
            rtmp_publish_domains test.uplive.ks-cdn.com;
            rtmp_play_domains    test.rtmplive.ks-cdn.com test.live.ks-cdn.com;
            hls_play_domains     test.hlslive.ks-cdn.com test.live.ks-cdn.com;
            hdl_play_domains     test.hdllive.ks-cdn.com test.live.ks-cdn.com;
            unique_name          test;
            idle_timeout         20s;
            application live {
                hdl                 on;
    
                hls                 on;
                hls_fragment        5s;
                hls_playlist_length 15s;
            }
        }
    }
    
    http {
        include       includes/depend/mime.types;
        default_type  application/octet-stream;

        log_format    main  '$remote_addr - $remote_user [$time_local] "$request" '
                            '$status $body_bytes_sent "$http_referer" '
                            '"$http_user_agent" "$http_x_forwarded_for"';

        access_log    /data/logs/blss/http_sla.log  main;

        keepalive_timeout  60;

        include       includes/depend/upstream.conf;

        server {
            listen 8080 reuseport;
            listen 80   reuseport;
    
            location / {
                hls  on;
                hdl  on;
    
                root /dev/shm;

                types {
                    application/vnd.apple.mpegurl m3u8;
                    video/mp2t ts;
                }
    
                add_header Access-Control-Allow-Origin *;
            }
        }
    }
