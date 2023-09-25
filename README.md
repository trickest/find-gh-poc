<h1 align="center">Find-gh-poc<a href="https://twitter.com/intent/tweet?text=Find-gh-poc%20-%20The%20centerpiece%20of%20the%20Trickest%20CVE%20project%3B%20finds%20CVE%20PoCs%20on%20Github%20%40trick3st%0Ahttps%3A%2F%2Fgithub.com%2Ftrickest%2Ffind-gh-poc"> <img src="https://img.shields.io/badge/Tweet--lightgrey?logo=twitter&style=social" alt="Tweet" height="20"/></a></h1>

<h3 align="center">
The centerpiece of the Trickest CVE project; finds CVE PoCs on Github. 
</h3>
<br>

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

[<img src="./banner.png" />](https://trickest.io/auth/register)
