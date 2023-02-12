# Proof-of-concept: `letsgo-nats`


## Introduction

NATS is a simple, secure and performant communications system for digital systems, services and devices.

### About `nats-server`


NATS servers can be deployed easily using the [`nats-server`](https://github.com/nats-io/nats-server) excutable:

```bash

Usage: nats-server [options]

Server Options:
    -a, --addr, --net <host>         Bind to host address (default: 0.0.0.0)
    -p, --port <port>                Use port for clients (default: 4222)
    -n, --name
        --server_name <server_name>  Server name (default: auto)
    -P, --pid <file>                 File to store PID
    -m, --http_port <port>           Use port for http monitoring
    -ms,--https_port <port>          Use port for https monitoring
    -c, --config <file>              Configuration file
    -t                               Test configuration and exit

[Many options are omitted...]

Common Options:
    -h, --help                       Show this message
    -v, --version                    Show version
        --help_tls                   TLS help
```

> Note that configuration can be provided as a configuration file using the `--config`  argument.

### Securing `nats-server`

In order to offer secure communications, administrator must deploy NATS using TLS encryption.

This is optional, and not enabled by default, but again, administrators MUST ensure that any "production deployment" uses TLS encryption.

TLS configuration is specified in the tls section of a configuration file, e.g:

```bash
    tls {
        cert_file:      "./certs/server-cert.pem"
        key_file:       "./certs/server-key.pem"
    }
```

## Problem

1. When running in TLS mode, NATS still expect clients to connect using raw TCP protocol, and then upgrade the TCP connection to a TLS connection.

    In other words, it's **not possible to serve NATS behind a reverse-proxy which terminates the TLS encryption.**

    > It's indicated in the documentation: https://docs.nats.io/running-a-nats-service/configuration/securing_nats/tls#tls-terminating-reverse-proxies

## Consequences

Any `nats-server` deployed in production must have access to and be configured to use a valid TLS certificate !

This certificate must also be renewed before it expires.

> Most of the time, certificates are issued for a period of 90 days, so any administrator planning to run NATS for more than 3 months will face the problem of certificate expiration and certificate renewal.

In order to use TLS encryption, it is necessary to:
- configure NATS to use existing TLS certificates
- reload NATS server on certificate renewal (we prefer reloading over restarting to avoid downtime)

Doing so is not so easy to achieve, because in order to reload NATS server without downtime, a unix signal (`SIGHUP`) must be sent to the `nats-server` process.

## Existing solutions


- Official NATS Helm charts (K8S) rely on [cert-manager](https://cert-manager.io/) to automate certificate generation and renewal, but this solution is not adequate for non kubernetes deployment scenarios.

- When deploying NATS server as a [systemd service](https://github.com/nats-io/nats-server/blob/main/util/nats-server-hardened.service), it's possible to automate certificate generation and renewal using [`lego` CLI](https://go-acme.github.io/lego/usage/cli/renew-a-certificate/#automatic-renewal), and execute a [renew hook](https://go-acme.github.io/lego/usage/cli/renew-a-certificate/#running-a-script-afterward) to [reload NATS server](https://docs.nats.io/running-a-nats-service/nats_admin/signals#reload-server-configuration) when new certificates are received. This solution is not adequate for docker deployment scenarios.

- When deploying NATS server using Docker, it's possible to rely on a similar solution than with systemd. Use volumes to mount certificates into the container, and when new certificates are received instead of sending a `SIGHUP` signal to NATS server directly, restart the docker container, or exec into the container in order to send a `SIGHUP` signal.

>There is no solution which "fits" all deployment scenarios.

## Proposed solution

Extend nats-server to include TLS certificates generation and renewal logic as part of the process.

## Proposed implementation

- Create custom nats-server binary using the [library interface](https://github.com/nats-io/nats-server/blob/7afddb3aac1b391f887137f84197024995a8886a/main.go#L98) to integrate TLS certificate generation.

- Rely on [Lego](https://github.com/go-acme/lego) project to generate TLS certificates

> [letsgo](https://github.com/charbonnierg/letsgo) is an example of how to use [Lego](https://github.com/go-acme/lego) within a Go project.

- Rely on [Chrono](https://github.com/procyon-projects/chrono) project to run tasks periodically.

## Proof-of-concept

A proof-of-concept implementation is available in [./letsgo-nats.go](./letsgo-nats.go).

Start-up order:

1. Parse Let's encrypt configuration from environment variables
2. Attempt to read existing certificates (according to config)
3. If certificate exists:
   1. Check if certiciate expiration date
   2. If certificate is not valid or certificate will expire soon, generate certificates
4. Parse command line arguments (--help / --version are parsed AFTER certificate generation)
5. Parse NATS server configuration
6. Initialize NATS server
7. Start NATS server
8. Wait until server is ready for connection
9. Schedule certificates expiration check every 24 hours (first task is executed immediately)
10. Wait for server shutdown


### Configuration

- ACME-related options can only be configured through environment variables. Only NATS-related command line arguments are supported.

#### DNS Provider Authentication

| Environment Variable    | Optional | Default           | Description                                      |
| ----------------------- | -------- | ----------------- | ------------------------------------------------ |
| `DNS_AUTH_TOKEN_VAULT`  | ✅        |                   | Name or URI of Azure Keyvault holding auth token |
| `DNS_AUTH_TOKEN_SECRET` | ✅        | `"do-auth-token"` | Name of secret stored in Azure Keyvault          |
| `DNS_AUTH_TOKEN_FILE`   | ✅        |                   | Path to file holding auth token                  |
| `DNS_AUTH_TOKEN`        | ✅        |                   | Auth token value                                 |

> 💥 At least one of `DNS_AUTH_TOKEN_VAULT`, `DNS_AUTH_TOKEN_FILE`, or `DNS_AUTH_TOKEN` must be set to a non-null value


#### Certificate generation


| Environment Variable | Optional | Default | Description                                                                                                                                                                                                                                                |
| -------------------- | -------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DOMAINS`            | 💥        |         | Comma-separated list of domain names                                                                                                                                                                                                                       |
| `FILENAME`           | ✅        |         | Name under which certificate files will be stored. Default to the first domain found within `DOMAINS` envionment variable, after replacing `*` with `_`. This variable is not used when requesting the certificate, only when criting certificate to file. |
| `OUTPUT_DIRECTORY`   | ✅        |         | Directory under which certificate files will be stored. Default to current working directory. If `OUTPUT_DIRECTORY` is configured and does not exist yet, it will be created with `511` permission.                                                        |


> `DOMAINS` environment variable must be set to a non-null value.

#### Let's Encrypt Account


| Environment Variable | Optional | Default           | Description                                                                                 |
| -------------------- | -------- | ----------------- | ------------------------------------------------------------------------------------------- |
| `ACCOUNT_EMAIL`      | 💥        |                   | Email of Let's Encrypt account for which certificate is issued                              |
| `ACCOUNT_KEY_FILE`   | ✅        | `"./account.key"` | Path to account key file. If account key does not exist, it is generated and saved to path. |
| `LE_TOS_AGREED`      | ✅        | `true`            | Agree to Let's Encrypt terms of usage                                                       |

> `ACCOUNT_EMAIL` environment variable must be set to a non-null value.

#### CA Directory


| Environment Variable | Required | Default     | Description                                                                                                                                                                                                                                                          |
| -------------------- | -------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CA_DIR`             | ✅        | `"STAGING"` | Name of CA directory environment or URL to CA directory. Allowed values are [PRODUCTION](https://letsencrypt.org/certificates/), [STAGING](https://letsencrypt.org/docs/staging-environment/), [TEST](https://hub.docker.com/r/containous/boulder), or any http URL. |
| `LE_CRT_KEY_TYPE`    | ✅        | `"RSA2048"` | Certificate key type. Both Let's Encrypt staging and production environments use the `RSA2048` key type.                                                                                                                                                             |

#### DNS Challenge

| Environment Variable | Optional | Default | Description                                                                                                                                                     |
| -------------------- | -------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DNS_RESOLVERS`      | ✅        |         | A comma-separated list of DNS resolvers used to verify challenge in `host:port` format                                                                          |
| `DNS_TIMEOUT`        | ✅        |         | Timeout in seconds for DNS challenge resolution                                                                                                                 |
| `DISABLE_CP`         | ✅        | `true`  | Disable complete propagation check, I.E, only a single resolver must verify the DNS challenge to succeed. When enbled, all resolvers must verify the challenge. |

### NATS Configuration

NATS TLS configuration blocks must be coherent with `DOMAINS`, `FILENAME` and `OUTPUT_DIRECTORY` when specified.

Aside from that, the `letsgo-nats` binary behaves just like NATS.

## Current limitations

- If certificate renewal fails, it is not retried. Instead, certificate will be requested on next schedule, I.E, 24 hours later. If certificates are requested 21 days before they expire, it means that there can be up to 20 attempts before certificate is expired. `(Low priority)`.

- Let's Encrypt configuration is parsed from environment only (`Low priority`).

- Only DigitalOcean DNS provider is supported at the moment. This was done by design to reduce the size of the executable (`Medium priority`).

- If a certificate issued by a different CA than target CA (possibly untrusted) exists and is valid, no certificate is generatedand no warning/error is raised. `(Medium priority)`.

- NATS Options are parsed AFTER TLS certificates are generated. It does not seem easy to bypass this limitation without writing much code (`Medium priority`). 

- It's possible to misconfigure application because configuration is redundant at some places (`HIGH priority`):
  - Certificates are generated according to Let's Encrypt config
  - Certificates are loaded by NATS according to NATS config
  - NATS fails to start if there is a configuration mismatch


## Conclusion

Even though this POC requires some configuration, and it's possible to have a configuration mismatch, it reduces a lot of complexity when deploying NATS servers on mixed environments.

For example, if we want to deploy NATS server as an Azure Container Instance, we should be able to allow container instance to access a keyvault, and can put the DNS Provider secret into a keyvault. When deploying, we only need to:

- specify `DNS_AUTH_TOKEN_VAULT` and `DNS_AUTH_TOKEN_SECRET` propertly.
- Mount a volume with fileshare backend holding NATS configuration OR use commands to specify options
- Mount a volume with fileshare backend to store certificates (security concerns to be discussed)

> It's important to store certificates within a volume to avoid requesting new certificates on each startup. Volume for configuration is optional since configuration can be provided as command line arguments.


## Going further

- Draft a specification for configuration and implement it

- Embbed a file server to optionally host web applications
