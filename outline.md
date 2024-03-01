0. tranco
1. `run.py`
    - `zdns`
    - `zmap`
    - `zgrab2 TLS and HTTP`
        - uses `get-ticket-for-grouping.ini`
2. import data into neo4j
    1. `generate_bulk_csv.py`
    2. `import_csv.sh`
    3. `generate_wcc.sh`
3. cluster/sample using `sampling_neo4j.py`
    - calls `zgrab2 http --use-tls`
    - for each domain
        - for all source IPs
            - sample 10 IPv4 targets in 1.2
            - sample 10 IPv4 targets in 1.3
            - sample 10 IPv6 targets in 1.2
            - sample 10 IPv6 targets in 1.3
    - number of connections is at most `(domains*sourceIPs)*40`
        - `domains` is 825896 (cf `MATCH (n:DOMAIN) RETURN COUNT(n)` in neo4j)
        - `sourceIPs` is 2.25 on average (cf resolve_stats.py)
        - -> ca 74_330_640 connections (NB: this is not exact, as the sourceIPs stat was created over all 1M domains)
4. distinguish cases
    - no resumption -> safe
    - resumed
        - shows original website -> ok
        - redirects to original website -> ok
        - shows other website -> insecure

Determining if same website

- both  200: check same title/body
- both  3xx: check same location header
- 200 + 3xx: check location header to ticket issuer

_IF_ we notice that redirection has different statistics in 1.3 and 1.2, we need to change scanning procedure; Then we want to behave similar to IPv4 vs IPv6.
