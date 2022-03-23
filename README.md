# Find-gh-poc
The centerpiece of the [trickest/cve](https://github.com/trickest/cve) project; finds CVE POCs in Github. 
## Installation
### From binary
Download a prebuilt binary from the [releases page](https://github.com/trickest/find-gh-poc/releases/latest) and unzip it.

### From source
Go version 1.17 is recommended.
```
go install -v github.com/trickest/find-gh-poc@latest
```

### Docker
```
docker pull quay.io/trickest/find-gh-poc
```

## Command line options
```
  -query-string string
    	GraphQL search query
  -query-file string
    	File to read GraphQL search query from
  -adjust-delay
    	Automatically adjust time delay between requests
  -delay int
    	Time delay after every GraphQL request [ms]
  -silent
    	Don't print JSON output to stdout
  -token-string string
    	Github token
  -token-file string
    	File to read Github token from
  -o string
    	Output file name
```

## Query examples
- cve-2022
- cve-2022-1234
- jenkins

## Note on Results
Depending on the search query, the results will most likely contain a few false positives (either PoCs of other CVEs or irrelevant repositories). Find-gh-poc outputs all of the query results without (currently) trying to filter them. We recommend that you use the results as a starting point and do your own filtering as you see fit for your use case.

## References
https://github.com/trickest/cve
