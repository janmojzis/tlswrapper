# how-to simply implement STARTTLS to the qmail-send

## 1. patch qmail
[examples/qmail-smtpd-starttls.patch](examples/qmail-smtpd-starttls.patch)

## 2. run script
~~~bash
exec softlimit -m 64000000 -f 100000000 \
tcpserver -HRDl0 0 25 \
/usr/bin/tlswrapper -u qmaild -vv -n -f /etc/ssl/sslcert.pem \
/usr/sbin/qmail-smtpd
~~~

## 3. check it using python3 script
~~~python
host=<your host>
server = smtplib.SMTP(host, 25)
server.set_debuglevel(True)
server.ehlo()
server.starttls()
print(ssl.DER_cert_to_PEM_cert(server.sock.getpeercert(True)))
server.ehlo()
server.quit()
~~~
