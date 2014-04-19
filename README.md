# ssl-heartbleed.nse

A variant of Patrik Karlsson's [ssl-heartbleed script][1] for Nmap.

The detection script is, effectively, the same.

The reporting script aids in aggregating detection results.

Please note that StartTLS-using protocols are not supported.

# usage

Invoke nmap, specifying the detection and reporting scripts.

```text
$ nmap -T4 -p T443,T8443 --script /path/to/my-ssl-heartbleed-detect.nse,/path/to/my-ssl-heartbleed-report.nse 192.168.1.0/24 > report.txt
```

Since the report will be long, extract the lines that were inserted by the reporting script:

```text
$ cat report.txt | grep -F ";VULNERABLE"
|   192.168.1.1:443;CVE-2014-0160 OpenSSL Heartbleed Bug;VULNERABLE
|_  192.168.1.8:443;CVE-2014-0160 OpenSSL Heartbleed Bug;VULNERABLE
$ cat report.txt | grep -F ";VULNERABLE" | sed -e 's#^....##' | cut -f1 -d;
192.168.1.1:443
192.168.1.8:443
```

The format of the report lines is "ipv4:port;vuln_title;vuln_state".

[1]: https://svn.nmap.org/nmap/scripts/ssl-heartbleed.nse
