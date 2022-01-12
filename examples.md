## run qmail-smtpd SMTPS service on port 465, authorization using client certs
~~~bash
RELAYCLIENT=''; export RELAYCLIENT
exec softlimit -m 64000000 -f 100000000 \
tcpserver -HRDl0 -c10 0.0.0.0 465 \
/usr/bin/tlswrapper -u qmaild -v -f /etc/ssl/sslcert.pem  -a /etc/ssl/ca.pem \
/usr/sbin/qmail-smtpd
~~~

## run dovecot IMAPS service on port 993, authorization using client certs, and run under user extracted from client certificate from commonName
~~~bash
exec softlimit -m 64000000 -f 100000000 \
tcpserver -HRDl0 0.0.0.0 993 \
/usr/bin/tlswrapper -U commonName -f /etc/ssl/sslcert.pem  -a /etc/ssl/ca.pem \
/usr/lib/dovecot/imap
~~~

## run qmail-smtpd SMTP service with STARTTLS enabled (without patching QMAIL)
~~~bash
exec softlimit -m 64000000 -f 100000000 \
tcpserver -HRDl0 0 25 \
/usr/bin/tlswrapper -u qmaild -v -n -f /etc/ssl/sslcert.pem \
/usr/bin/tlswrapper-smtp -v \
/usr/sbin/qmail-smtpd
~~~
~~~python
# check if it works
host=<your host>
server = smtplib.SMTP(host, 25)
server.set_debuglevel(True)
server.ehlo()
server.starttls()
print(ssl.DER_cert_to_PEM_cert(server.sock.getpeercert(True)))
server.ehlo()
server.quit()
~~~
