# dnsss

DNS Server Selection algorithm demonstrations.

## Requirements

- Python 3.13
- See requirements.txt

## Bind algorithm

Basic Usage:

```sh
python3 -m dnsss.bind example.com
```

Press enter to repeat query.

Advanced Usage Example.

Read from config file (see config.example.yml), query every 100ms for 500 queries, make it pretty.

```sh
python3 -m dnsss.bind example.com -f config.yml -n 0.1 -c 500 | jq
```

## AR1 autoregression algorithm

Basic Usage:

```sh
python3 -m dnsss.ar1 example.com
```

## References

- S. Deb, A. Srinivasan and S. Kuppili Pavan, "An improved DNS server selection algorithm for faster lookups,"
  2008 3rd International Conference on Communication Systems Software and Middleware and Workshops
  (COMSWARE '08), Bangalore, India, 2008, pp. 288-295, doi: 10.1109/COMSWA.2008.4554428.
  https://ieeexplore.ieee.org/document/4554428
