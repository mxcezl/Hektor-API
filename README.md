# Hektor - Your subdomain API scanner

Hektor is a tool to automate the process of gathering subdomains from different sources and then scanning them for vulnerabilities. It's written in Python3 and uses the [dnsdumpster](https://github.com/PaulSec/API-dnsdumpster.com).

## Installation

Run HektorAPI with Docker:

```bash
docker build -t hektor-api .
docker run --env-file .\.env -p 5000:5000 hektor-api
```

You need to create a .env file with the following variables in the root directory of the project:

```bash
JWT_SECRET_KEY=JWT_SECRET_KEY
ADMIN_PASSWORD=ADMIN_PASSWORD
MONGODB_USERNAME=MONGODB_USERNAME
MONGODB_PASSWORD=MONGODB_PASSWORD
MONGODB_URL=MONGODB_URL
MONGODB_DB=MONGODB_DB
```

> **Note:** You need to replace the values with your own.