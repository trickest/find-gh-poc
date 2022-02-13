package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/shurcooL/githubv4"
)

const (
	CVERegex = "(?i)cve[-–][0-9]{4}[-–][0-9]{4,}"
)

var ReadmeQuery struct {
	Repository struct {
		Object struct {
			Blob struct {
				Text string
			} `graphql:"... on Blob"`
		} `graphql:"object(expression: \"HEAD:README.md\")"`
	} `graphql:"repository(owner: $owner, name: $name)"`
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

var CVEQuery struct {
	Search struct {
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
	Search struct {
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
			fmt.Println(err)
			return ""
		}
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
		fmt.Println(err)
		return
	}

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
		time.Sleep(time.Second)

		err = githubV4Client.Query(context.Background(), &CVEPaginationQuery, variables)
		if err != nil {
			fmt.Println(err)
		}

		if len(CVEPaginationQuery.Search.Edges) == 0 {
			fmt.Println("\nLimit of 1000 results reached!")
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

func main() {
	token := flag.String("token", "", "Github token")
	query := flag.String("query-string", "", "GraphQL search query")
	queryFile := flag.String("query-file", "", "File to read GraphQL search query from")
	outputFolder := flag.String("o", "", "Output folder name")
	silent := flag.Bool("silent", false, "Don't print JSON output to stdout")
	flag.Parse()

	go func() {
		signalChannel := make(chan os.Signal, 1)
		signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)
		<-signalChannel

		fmt.Println("\nProgram interrupted, exiting...")
		os.Exit(0)
	}()

	if *token == "" || *outputFolder == "" {
		fmt.Println("Token and output folder must be specified!")
		os.Exit(1)
	}

	if *query == "" && *queryFile == "" {
		fmt.Println("Query must be specified!")
		os.Exit(1)
	}

	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: *token},
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

		dirInfo, err := os.Stat(*outputFolder)
		dirExists := !os.IsNotExist(err) && dirInfo.IsDir()

		if !dirExists {
			err = os.Mkdir(*outputFolder, 0755)
			if err != nil {
				fmt.Println("Couldn't create directory to store files!")
				os.Exit(1)
			}
		}

		for id, repoURLs := range reposPerCVE {
			cveFile, err := os.Create(path.Join(*outputFolder, id+".txt"))
			if err != nil {
				fmt.Println("Couldn't create file for " + id + "!")
				continue
			}

			for _, r := range repoURLs {
				_, _ = io.WriteString(cveFile, r+"\n")
			}
		}

		if !*silent {
			data, _ := json.MarshalIndent(reposResults, "", "   ")
			fmt.Println(string(data))
		}
	}
}
