# dnsss

DNS Server Selection algorithm demonstrations.

## Install

- Requires Python 3.13
- Create a virtual environment and install requirements.txt

## Usage

Basic usage:

```sh
python3 -m dnsss
```

This starts in interactive mode using system resolvers and the `bind` algorithm.
Press `<enter>` to execute a query, and `?` to see available commands.

To see all command line options, run:

```sh
python3 -m dnsss -h
```

### Examples

Specify config file and algorithm:

```sh
python3 -m dnsss -f config.yml -a ar1
```

In interactive mode, type `s` to save the state to a file `state.<alg>.yml`, e.g. `state.ar1.yml`.

You can specify a different filename with `-o output.yml`.

To save the file automatically, provide the `-s` flag.

To load the state file, specify the `-l` parameter.

To load from one file and save to another, you can do `-l load.yml -o output.yml`.

To run queries at an interval, you can specify the `-n` parameter, or adjust interactively
using `+`/`-`. To run a specific number of queries and quit, use `-c`.

## Config File

Config file reference.

### `servers`

A non-empty list of default server addresses. Example:

```yaml
servers:
  - 8.8.8.8
  # Optional port
  - 127.0.0.1@5353
```

If not provided, the system resolvers are used.

### `rules`

A list of domain rule configs. Example:

```yaml
rules:
  - domain: domain.internal
    servers:
      - 10.0.0.1
      - 10.0.0.2
    exclude:
      - ext.domain.internal
```

### `questions`

A list of DNS questions or references to files from which to load them. Example:

```yaml
questions:
  # Defaults to an A record
  - plato.stanford.edu
  - burgers.internal AAAA
  # Reverse PTR
  - 129.6.15.28 PTR
  - 1.96.163.132.in-addr.arpa PTR
  # File reference
  - '@questions.dns'
```

### `params`

An optional map to configure the algorithm parameters. See each algorithm for
supported data. Extra/unknown keys are ignored. Example:

```yaml
params:
  # See bind resolver
  g: 0.98
  # See ar1 resolver
  alpha_min: 0.1
  alpha_max: 0.9
```

If no values are provided, it defaults to `google.com`. For file syntax, see `questions.example.dns`.

### `anomalies`

A list of latency injection config mappings. Example:

```yaml
anomalies:
  - # The number of queries to remain active
    limit: 100
    delayers:
      - # Server regex to target
        pattern: '10\.123'
        # The delay to add
        delay: 0.01
  # This removes any delay for the next 100 queries
  - limit: 100
  # A limit of 0 will be skipped
  - limit: 0
    # These won't run
    delayers:
      - pattern: .*
        delay: 0.5
  # A null/missing limit means run forever
  - limit: null
    delayers:
      - pattern: '192.168'
        delay: 0.001
```


### Other Config

```yaml
# Default/max timeout seconds
timeout_max: 5.0
# Minimum timeout seconds
timeout_min: 1.0
# Maximum number of retries for timeouts
retries_max: 3
# Whether to use TCP for DNS queries
tcp: false
# Some CLI options can be set as defaults
options:
  algorithm: AR1
  # ...
```

## References

- S. Deb, A. Srinivasan and S. Kuppili Pavan, "An improved DNS server selection algorithm for faster lookups,"
  2008 3rd International Conference on Communication Systems Software and Middleware and Workshops
  (COMSWARE '08), Bangalore, India, 2008, pp. 288-295, doi: 10.1109/COMSWA.2008.4554428.
  https://ieeexplore.ieee.org/document/4554428
    
- Welford's online algorithm
  https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford%27s_online_algorithm

- "Accurately computing running variance"
  https://www.johndcook.com/blog/standard_deviation/