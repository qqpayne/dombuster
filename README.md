# DomBuster

Command line utility to search for subdomains in open sources. Named by analogy with OWASP DirBuster. Also, it just sounds funny. Usable for various network researches and penetration testing.

### Features
* Simple to use
* Multi-threaded and fast
* Can be used with private API keys 
* Fancy appearance
* Can provide you with various data about subdomains

### Screenshot
![DomBuster](https://i.imgur.com/rdPq8FT.png)

### Installation

```
git clone https://github.com/qqpayne/dombuster.git
```

### Examples

* To enumerate subdomains of specific domain and save results to txt:

``dombuster.py example.com output.txt``

* To enumerate subdomains of specific domain and save only that subdomains, who respond to ping:

``dombuster.py --strict example.com output.txt``

* To enumerate subdomains of specific domain and resolve their IP addreses and organization name, save to csv:

``dombuster.py  --ip --org --csv example.com output.csv``

* To enumerate subdomains of specific domain using your API keys:

``dombuster.py example.com output.txt -k keys.json``

### License

DomBuster is licensed under the Apache 2.0 license. take a look at the [LICENSE](https://github.com/qqpayne/dombuster/blob/main/LICENSE) for more information.

