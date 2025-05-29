# DNS Client
A simple DNS client written in Clojure.
## Features
- Query DNS servers for NS, A, PTR, AAAA, CNAME, SOA, MX, and ANY records.
- returns data similar to `dig` command output.
- Supports tracing DNS queries through root servers.
## Installation
To use this DNS client, you can clone the repository and run it using Clojure CLI tools. Ensure you have Clojure installed on your system.
## Usage
To use the DNS client, you can call the `query-dns-server` function with the appropriate parameters. For example:
```clojure
(require '[dns-client.main :as dns])
(dns/query-dns-server {:qtype dns/ns-qtype :dname "example.com"})
```
You can also run the main function with command-line arguments:
```bash
clj -M -m dns-client.main '{:qtype [0 1] :dname "discourse.doomemacs.org" :trace? true}'
```
## Testing
The project includes tests for the DNS client functionality. You can run the tests using:
```bash
clj -M:test
```
## License
This project is licensed under the MIT License. See the LICENSE file for details.
