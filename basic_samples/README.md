# Basic Samples

## Testing

### FTP
* `ftp test.rebex.net`
* `sftp demo@test.rebex.net`
* <https://test.rebex.net/>
* [Free Public FTP Servers](https://www.sftp.net/public-online-ftp-servers)

### SMTP
* [Free SMTP Server for Testing](https://www.wpoven.com/tools/free-smtp-server-for-testing)
* Test connectivity: `nc -v smtp.freesmtpservers.com 25`
* Simulate SMTP Interaction (Sending Test Email)
```
telnet localhost 25 (or your mail server IP, smtp.freesmtpservers.com)
EHLO localhost
MAIL FROM: <sender@example.com>
RCPT TO: <recipient@example.com>
DATA
Subject: Test Subject
This is a test email.
. (a single period on a new line)
QUIT 
```

### HTTP
* Connect to <http://httpforever.com/>

### HTTP2
* Test support `curl --http2 -sI https://http2cdn.cdnsun.com`
* [HTTP/2](https://hpbn.co/http2/)
* [HTTP/2 Protocol in Plain English using Wireshark](https://community.f5.com/kb/technicalarticles/http2-protocol-in-plain-english-using-wireshark/281447)+
* [http2 in curl](https://http2-explained.haxx.se/en/part11)

### HTTP3
* Needs curl rebuild: `curl --http3-only https://example.org:4433/`
* [HTTP/3 with curl](https://curl.se/docs/http3.html)
* [HTTP/3](https://everything.curl.dev/http/versions/http3.html)
* [HTTP/3 check](https://http3check.net/)

### HTTPS
* Close Chrome / Firefox
* `export SSLKEYLOGFILE=~/.ssl-key.log`
* Launch Chrome / Firefox
* Browse websites. The `~/.ssl-key.log` file will be populated with keys.
* Configure Wireshark: Go to Edit -> Preferences -> Protocols -> TLS and set the "(Pre)-Master-Secret log filename" to `~/.ssl-key.log`
* [K50557518: Decrypt SSL traffic with the SSLKEYLOGFILE environment variable on Firefox or Google Chrome using Wireshark](https://my.f5.com/manage/s/article/K50557518)

### Captured communications test data
* <https://malware-traffic-analysis.net/>
* [wireshark: SampleCaptures](https://wiki.wireshark.org/samplecaptures)