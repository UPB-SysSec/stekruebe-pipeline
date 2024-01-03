0. tranco
1. `run.sh` **TODO** measure where hosts get lost
    - `zdns`
    - `zmap`
    - `zgrab2 TLS` **TODO** 1.2 or 1.3 or both?
2. import data into neo4j
    1. `generate_bulk_csv.py`
    2. `import_csv.sh`
3. cluster using `sampling_neo4j.py`
    - calls `scan.py`
    - calls `zgrab2 http --use-tls` (2 times) **TODO** 1.2 or 1.3 or both?
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
