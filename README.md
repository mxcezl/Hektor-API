# Hektor - Your subdomain API scanner

Hektor is a tool to automate the process of gathering subdomains from different sources and then scanning them for vulnerabilities. It's written in Python3 and uses the [dnsdumpster](https://github.com/PaulSec/API-dnsdumpster.com).

## Installation

First, install `dnsdumpster`:

```bash
pip install https://github.com/PaulSec/API-dnsdumpster.com/archive/master.zip --user
```

Then install other dependencies:

```bash
pip install -r requirements.txt
```