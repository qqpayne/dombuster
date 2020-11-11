# DomBuster

Command line utility to search for subdomains in open sources. Named by analogy with OWASP DirBuster. Also, it just sounds funny.

### Installation

```
git clone https://github.com/qqpayne/dombuster.git
```

### Examples

* To enumerate subdomains of specific domain and save results to txt:

``dombuster.py example.com output.txt``

* To enumerate subdomains of specific domain and save only that subdomains, who respond to ping:

``dombuster.py --strict example.com``

* To enumerate subdomains of specific domain using your API keys:

``dombuster.py example.com -k keys.json``

### License

DomBuster is licensed under the Apache 2.0 license. take a look at the [LICENSE](https://github.com/qqpayne/dombuster/blob/main/LICENSE) for more information.

