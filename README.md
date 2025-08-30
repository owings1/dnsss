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

This starts in interactive mode using the `config.example.yml` file and the `bind` algorithm.
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

The main config file keys are `servers`, `params`, and `questions`.

### Servers

A non-empty list of server IP addresses. Example:

```yaml
servers:
  - 8.8.8.8
  - 8.8.4.4
  - 1.1.1.1
  - 129.250.35.250
  - 208.67.222.222
```

### Params

An optional map to configure the algorithm parameters. See each algorithm for
supported data. Extra/unknown keys are ignored. Example:

```yaml
params:
  # See bind resolver
  g: 0.98
  o: 0.05
  # See bmod resolver
  k: 4
  # See ar1 resolver
  alpha_min: 0.1
  alpha_max: 0.9
```

### Questions

A list of DNS questions or references to files from which to load them. Example:

```yaml
questions:
  # Defaults to an A record
  - plato.stanford.edu
  - google.com TXT
  - burgers.internal AAAA
  # File reference
  - '@questions.dns'
```

If no values are provided, it defaults to `google.com`. For file syntax, see `questions.example.dns`.

### Other Config

```yaml
# Default timeout seconds
timeout: 5.0
# Whether to use TCP for DNS queries
tcp: false
```

## References

- S. Deb, A. Srinivasan and S. Kuppili Pavan, "An improved DNS server selection algorithm for faster lookups,"
  2008 3rd International Conference on Communication Systems Software and Middleware and Workshops
  (COMSWARE '08), Bangalore, India, 2008, pp. 288-295, doi: 10.1109/COMSWA.2008.4554428.
  https://ieeexplore.ieee.org/document/4554428
