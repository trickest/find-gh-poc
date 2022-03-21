package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/oauth2"

	"github.com/schollz/progressbar/v3"
	"github.com/shurcooL/githubv4"
)

const (
	CVERegex = "(?i)cve[-–_][0-9]{4}[-–_][0-9]{4,}"
)

type RateLimit struct {
	Limit     int
	Remaining int
	Cost      int
	ResetAt   time.Time
}

type Repository struct {
	Url              string
	Description      string
	IsEmpty          bool
	RepositoryTopics struct {
		Nodes []struct {
			Topic struct {
				Name string
			}
		}
	} `graphql:"repositoryTopics(first: 100)"`
}

type RepositoryResult struct {
	CVEIDs      []string `json:"cves,omitempty"`
	Url         string   `json:"url"`
	Description string   `json:"description"`
	Topics      []string `json:"topics,omitempty"`
	Readme      *string  `json:"readme,omitempty"`
}

var ReadmeQuery struct {
	RateLimit  RateLimit `graphql:"rateLimit"`
	Repository struct {
		Object struct {
			Blob struct {
				Text string
			} `graphql:"... on Blob"`
		} `graphql:"object(expression: \"HEAD:README.md\")"`
	} `graphql:"repository(owner: $owner, name: $name)"`
}

var CVEQuery struct {
	RateLimit RateLimit `graphql:"rateLimit"`
	Search    struct {
		RepositoryCount int
		PageInfo        struct {
			EndCursor   githubv4.String
			StartCursor githubv4.String
		}
		Edges []struct {
			Node struct {
				Repo Repository `graphql:"... on Repository"`
			}
		}
	} `graphql:"search(query: $query, type: REPOSITORY, first: 100)"`
}

var CVEPaginationQuery struct {
	RateLimit RateLimit `graphql:"rateLimit"`
	Search    struct {
		RepositoryCount int
		PageInfo        struct {
			EndCursor   githubv4.String
			StartCursor githubv4.String
		}
		Edges []struct {
			Node struct {
				Repo Repository `graphql:"... on Repository"`
			}
		}
	} `graphql:"search(query: $query, type: REPOSITORY, first: 100, after: $after)"`
}

var (
	reposResults     []RepositoryResult
	httpClient       *http.Client
	githubV4Client   *githubv4.Client
	reposPerCVE      map[string][]string
	githubCreateDate = time.Date(2008, 2, 8, 0, 0, 0, 0, time.UTC)
	bar              = &progressbar.ProgressBar{}
	barInitialized   = false
	requestDelay     int
	adjustDelay      bool
	rateLimit        *RateLimit
	delayMutex       = &sync.Mutex{}
	outputFile       string
	silent           bool
)

func getReadme(repoUrl string) string {
	ReadmeQuery.Repository.Object.Blob.Text = ""
	urlSplit := strings.Split(repoUrl, "/")
	if len(urlSplit) == 5 {
		variables := map[string]interface{}{
			"owner": githubv4.String(strings.Trim(urlSplit[len(urlSplit)-2], " ")),
			"name":  githubv4.String(strings.Trim(urlSplit[len(urlSplit)-1], " ")),
		}

		err := githubV4Client.Query(context.Background(), &ReadmeQuery, variables)
		if err != nil {
			rateLimit = &ReadmeQuery.RateLimit
			handleGraphQLAPIError(err)
		}
		delayMutex.Lock()
		rateLimit = &ReadmeQuery.RateLimit
		time.Sleep(time.Millisecond * time.Duration(requestDelay*rateLimit.Cost))
		delayMutex.Unlock()

		return ReadmeQuery.Repository.Object.Blob.Text
	} else {
		return ""
	}
}

func getRepos(query string, startingDate time.Time, endingDate time.Time) {
	querySplit := strings.Split(query, "created:")
	query = strings.Trim(querySplit[0], " ") + " created:" +
		startingDate.Format(time.RFC3339) + ".." + endingDate.Format(time.RFC3339)
	variables := map[string]interface{}{
		"query": githubv4.String(query),
	}

	err := githubV4Client.Query(context.Background(), &CVEQuery, variables)
	if err != nil {
		rateLimit = &CVEQuery.RateLimit
		handleGraphQLAPIError(err)
	}
	delayMutex.Lock()
	rateLimit = &CVEQuery.RateLimit
	time.Sleep(time.Millisecond * time.Duration(requestDelay*rateLimit.Cost))
	delayMutex.Unlock()

	maxRepos := CVEQuery.Search.RepositoryCount
	if !barInitialized {
		bar = progressbar.NewOptions(maxRepos,
			progressbar.OptionSetDescription("Downloading results..."),
			progressbar.OptionSetItsString("res"),
			progressbar.OptionShowIts(),
			progressbar.OptionShowCount(),
			progressbar.OptionOnCompletion(func() { fmt.Println() }),
		)
		barInitialized = true
		if adjustDelay {
			go func() {
				for {
					delayMutex.Lock()
					remainingRepos := bar.GetMax() - len(reposResults)
					remainingRequests := remainingRepos + remainingRepos/100 + 1
					if remainingRequests < rateLimit.Remaining {
						requestDelay = 0
						delayMutex.Unlock()
						break
					} else {
						untilNextReset := rateLimit.ResetAt.Sub(time.Now()).Milliseconds()
						if untilNextReset < 0 {
							untilNextReset = time.Hour.Milliseconds()
						}
						if rateLimit.Remaining == 0 {
							writeOutput(outputFile, silent)
							fmt.Println("Rate limit exceeded!\nNext reset at " + rateLimit.ResetAt.Format(time.RFC1123))
							os.Exit(0)
						}
						requestDelay = int(untilNextReset)/rateLimit.Remaining + 1
					}
					delayMutex.Unlock()
				}
			}()
		}
	}
	if maxRepos >= 1000 {
		dateDif := endingDate.Sub(startingDate) / 2
		getRepos(query, startingDate, startingDate.Add(dateDif))
		getRepos(query, startingDate.Add(dateDif), endingDate)
		return
	}
	reposCnt := 0
	for _, nodeStruct := range CVEQuery.Search.Edges {
		if nodeStruct.Node.Repo.IsEmpty {
			continue
		}
		var topics = make([]string, 0)
		for _, node := range nodeStruct.Node.Repo.RepositoryTopics.Nodes {
			topics = append(topics, node.Topic.Name)
		}
		readme := getReadme(nodeStruct.Node.Repo.Url)

		reposResults = append(reposResults, RepositoryResult{
			Url:         nodeStruct.Node.Repo.Url,
			Description: nodeStruct.Node.Repo.Description,
			Topics:      topics,
			Readme:      &readme,
		})
		reposCnt++
		_ = bar.Add(1)
	}

	variables = map[string]interface{}{
		"query": githubv4.String(query),
		"after": CVEQuery.Search.PageInfo.EndCursor,
	}
	for reposCnt < maxRepos {
		err = githubV4Client.Query(context.Background(), &CVEPaginationQuery, variables)
		if err != nil {
			rateLimit = &CVEPaginationQuery.RateLimit
			handleGraphQLAPIError(err)
		}
		delayMutex.Lock()
		rateLimit = &CVEPaginationQuery.RateLimit
		time.Sleep(time.Millisecond * time.Duration(requestDelay*rateLimit.Cost))
		delayMutex.Unlock()

		if len(CVEPaginationQuery.Search.Edges) == 0 {
			break
		}
		for _, nodeStruct := range CVEPaginationQuery.Search.Edges {
			if nodeStruct.Node.Repo.IsEmpty {
				continue
			}
			var topics = make([]string, 0)
			for _, node := range nodeStruct.Node.Repo.RepositoryTopics.Nodes {
				topics = append(topics, node.Topic.Name)
			}
			readme := getReadme(nodeStruct.Node.Repo.Url)

			reposResults = append(reposResults, RepositoryResult{
				Url:         nodeStruct.Node.Repo.Url,
				Description: nodeStruct.Node.Repo.Description,
				Topics:      topics,
				Readme:      &readme,
			})
			reposCnt++
			_ = bar.Add(1)
		}

		variables["after"] = CVEPaginationQuery.Search.PageInfo.EndCursor
	}
}

func handleGraphQLAPIError(err error) {
	writeOutput(outputFile, silent)
	fmt.Println(err)
	if strings.Contains(err.Error(), "limit exceeded") {
		fmt.Println("Next reset at " + rateLimit.ResetAt.Format(time.RFC1123))
	}
	os.Exit(0)
}

func writeOutput(fileName string, silent bool) {
	if len(reposResults) == 0 {
		return
	}
	output, err := os.Create(fileName)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Couldn't create output file")
	}
	defer output.Close()

	for id, repoURLs := range reposPerCVE {
		for _, r := range repoURLs {
			_, _ = io.WriteString(output, id+" - "+r+"\n")
		}
	}

	if !silent {
		data, _ := json.MarshalIndent(reposResults, "", "   ")
		fmt.Println(string(data))
	}
}

func main() {
	token := flag.String("token-string", "", "Github token")
	tokenFile := flag.String("token-file", "", "File to read Github token from")
	query := flag.String("query-string", "", "GraphQL search query")
	queryFile := flag.String("query-file", "", "File to read GraphQL search query from")
	flag.StringVar(&outputFile, "o", "", "Output file name")
	flag.BoolVar(&silent, "silent", false, "Don't print JSON output to stdout")
	flag.IntVar(&requestDelay, "delay", 0, "Time delay after every GraphQL request [ms]")
	flag.BoolVar(&adjustDelay, "adjust-delay", false, "Automatically adjust time delay between requests")
	flag.Parse()

	go func() {
		signalChannel := make(chan os.Signal, 1)
		signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)
		<-signalChannel

		fmt.Println("\nProgram interrupted, exiting...")
		os.Exit(0)
	}()

	if (*token == "" && *tokenFile == "") || outputFile == "" {
		fmt.Println("Token and output file must be specified!")
		os.Exit(1)
	}

	if *query == "" && *queryFile == "" {
		fmt.Println("Query must be specified!")
		os.Exit(1)
	}
	githubToken := ""
	if *tokenFile != "" {
		file, err := os.Open(*tokenFile)
		if err != nil {
			fmt.Println("Couldn't open file to read token!")
			os.Exit(1)
		}
		defer file.Close()

		tokenData, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Println("Couldn't read from token file!")
			os.Exit(1)
		}

		githubToken = string(tokenData)
	} else {
		githubToken = *token
	}

	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubToken},
	)
	httpClient = oauth2.NewClient(context.Background(), src)
	githubV4Client = githubv4.NewClient(httpClient)
	reposResults = make([]RepositoryResult, 0)
	reposPerCVE = make(map[string][]string)

	searchQuery := *query
	if searchQuery == "" {
		file, err := os.Open(*queryFile)
		if err != nil {
			fmt.Println("Couldn't open file to read query!")
			os.Exit(1)
		}
		defer file.Close()

		queryData, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Println("Couldn't read from query file!")
			os.Exit(1)
		}

		searchQuery = strings.Trim(string(queryData), " \n\r\t")
	}

	searchQuery += " in:readme in:description in:name"
	getRepos(searchQuery, githubCreateDate, time.Now().UTC())

	if len(reposResults) > 0 {
		re := regexp.MustCompile(CVERegex)

		for i, repo := range reposResults {
			ids := make(map[string]bool, 0)

			matches := re.FindAllStringSubmatch(repo.Url, -1)
			matches = append(matches, re.FindAllStringSubmatch(repo.Description, -1)...)
			matches = append(matches, re.FindAllStringSubmatch(*repo.Readme, -1)...)
			for _, topic := range repo.Topics {
				matches = append(matches, re.FindAllStringSubmatch(topic, -1)...)
			}

			for _, m := range matches {
				if m != nil && len(m) > 0 {
					if m[0] != "" {
						m[0] = strings.ToUpper(m[0])
						m[0] = strings.ReplaceAll(m[0], "_", "-")
						ids[strings.ReplaceAll(m[0], "–", "-")] = true
					}
				}
			}

			if len(ids) > 0 {
				reposResults[i].CVEIDs = make([]string, 0)
				for id := range ids {
					reposResults[i].CVEIDs = append(reposResults[i].CVEIDs, id)
					reposPerCVE[id] = append(reposPerCVE[id], repo.Url)
				}
			}

			reposResults[i].Readme = nil
			reposResults[i].Topics = nil
		}

		writeOutput(outputFile, silent)
	}
}
