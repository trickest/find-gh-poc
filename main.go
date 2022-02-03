package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/shurcooL/githubv4"
)

type Repository struct {
	Url         string `json:"url"`
	Description string `json:"description"`
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
var httpClient *http.Client
var githubV4Client *githubv4.Client

func getRepos(query string) {
	variables := map[string]interface{}{
		"query": githubv4.String(query),
	}

	err := githubV4Client.Query(context.Background(), &CVEQuery, variables)
	if err != nil {
		fmt.Println(err)
	}

	maxRepos := CVEQuery.Search.RepositoryCount
	reposCnt := len(repos)
	bar := progressbar.NewOptions(maxRepos,
		progressbar.OptionSetDescription("Downloading results..."),
		progressbar.OptionSetItsString("res"),
		progressbar.OptionShowIts(),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
	)

	for _, nodeStruct := range CVEQuery.Search.Edges {
		repos = append(repos, nodeStruct.Node.Repo)
	}
	_ = bar.Add(len(CVEQuery.Search.Edges))

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
		}
		_ = bar.Add(len(CVEPaginationQuery.Search.Edges))

		reposCnt = len(repos)
		variables["after"] = CVEPaginationQuery.Search.PageInfo.EndCursor
	}

	data, _ := json.MarshalIndent(repos, "", "   ")

	err = ioutil.WriteFile(strings.Trim(query, "-*")+".json", data, 0644)
	if err != nil {
		fmt.Println("Couldn't save data into a file!")
	}
}

func main() {
	token := flag.String("token", "", "Github token")
	query := flag.String("query", "", "Query")
	flag.Parse()

	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: *token},
	)
	httpClient = oauth2.NewClient(context.Background(), src)
	githubV4Client = githubv4.NewClient(httpClient)
	repos = make([]Repository, 0)

	getRepos(*query)
}
