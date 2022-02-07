package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/oauth2"
	"io"
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

var illegalFileNameChars = [...]string{
	"<",
	">",
	":",
	"\"",
	"/",
	"\\",
	"|",
	"?",
	"*",
	" ",
	"}",
	"{",
	"#",
	"$",
	"%",
	"!",
	"`",
	"'",
	"@",
	"=",
	"+",
}

const (
	CVERegex = "(CVE(-|–)[0-9]{4}(-|–)[0-9]{4,})|(cve(-|–)[0-9]{4}(-|–)[0-9]{4,})"
)

type Repository struct {
	Url         string `json:"url"`
	Description string `json:"description"`
}

type RepositoryResult struct {
	CVEIDs      []string `json:"cves,omitempty"`
	Url         string   `json:"url"`
	Description string   `json:"description"`
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

var repos []Repository
var reposResults []RepositoryResult
var httpClient *http.Client
var githubV4Client *githubv4.Client
var reposPerCVE map[string][]string
var githubCreateDate = time.Date(2008, 2, 8, 0, 0, 0, 0, time.UTC)
var bar = &progressbar.ProgressBar{}
var barInitialized = false

func getRepos(query string, startingDate time.Time, endingDate time.Time) {
	querySplit := strings.Split(query, "created:")
	query = querySplit[0] + " created:" + startingDate.Format(time.RFC3339) + ".." + endingDate.Format(time.RFC3339)
	variables := map[string]interface{}{
		"query": githubv4.String(query),
	}

	err := githubV4Client.Query(context.Background(), &CVEQuery, variables)
	if err != nil {
		fmt.Println(err)
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
		repos = append(repos, nodeStruct.Node.Repo)
		reposCnt++
	}
	_ = bar.Add(reposCnt)

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
			repos = append(repos, nodeStruct.Node.Repo)
			reposCnt++
		}
		_ = bar.Add(len(CVEPaginationQuery.Search.Edges))

		variables["after"] = CVEPaginationQuery.Search.PageInfo.EndCursor
	}
}

func main() {
	token := flag.String("token", "", "Github token")
	query := flag.String("query", "", "GraphQL search query")
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

	if *token == "" || *outputFolder == "" || *query == "" {
		fmt.Println("All flags must be specified!")
		os.Exit(1)
	}

	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: *token},
	)
	httpClient = oauth2.NewClient(context.Background(), src)
	githubV4Client = githubv4.NewClient(httpClient)
	repos = make([]Repository, 0)
	reposResults = make([]RepositoryResult, 0)
	reposPerCVE = make(map[string][]string)

	getRepos(*query, githubCreateDate, time.Now().UTC())

	if len(repos) > 0 {
		re := regexp.MustCompile(CVERegex)

		for _, repo := range repos {
			ids := make(map[string]bool, 0)

			matches := re.FindAllStringSubmatch(repo.Url, -1)
			matches = append(matches, re.FindAllStringSubmatch(repo.Description, -1)...)

			for _, m := range matches {
				if m != nil && len(m) > 0 {
					if m[0] != "" {
						m[0] = strings.ToUpper(m[0])
						ids[strings.ReplaceAll(m[0], "–", "-")] = true
					}
				}
			}

			repoRes := RepositoryResult{
				Url:         repo.Url,
				Description: repo.Description,
			}
			if len(ids) > 0 {
				repoRes.CVEIDs = make([]string, 0)
				for id := range ids {
					repoRes.CVEIDs = append(repoRes.CVEIDs, id)
					reposPerCVE[id] = append(reposPerCVE[id], repo.Url)
				}
			}

			reposResults = append(reposResults, repoRes)
		}

		for _, char := range illegalFileNameChars {
			if strings.Contains(*outputFolder, char) {
				*outputFolder = strings.ReplaceAll(*outputFolder, char, "")
				fmt.Println("Illegal character ( " + char + " ) removed from folder name!")
			}
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
