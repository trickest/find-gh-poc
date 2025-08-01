package search

import (
	"context"
	"fmt"
	"time"

	"find-gh-poc/pkg/githubclient"

	"github.com/shurcooL/githubv4"
)

// Repository represents a GitHub repository
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

// SearchRepositories fetches all repositories matching the query with date range splitting
func SearchRepositories(ctx context.Context, client *githubclient.GitHubClient, query string) ([]Repository, error) {
	startingDate := time.Date(2008, 2, 8, 0, 0, 0, 0, time.UTC)
	endingDate := time.Now().UTC()

	searchQuery := query + " created:" + startingDate.Format(time.RFC3339) + ".." + endingDate.Format(time.RFC3339)
	repoCount, err := getRepositoryCount(ctx, client, searchQuery)
	if err != nil {
		return nil, err
	}

	if repoCount > 1000 {
		return fetchRepositoriesWithSplitting(ctx, client, query, startingDate, endingDate)
	}
	fmt.Printf("Repository count (%d) for date range %s to %s is less than 1000, fetching all repositories...\n", repoCount, startingDate.Format("2006-01-02"), endingDate.Format("2006-01-02"))
	return fetchRepositories(ctx, client, searchQuery)
}

// fetchRepositoriesWithSplitting recursively splits date ranges until each chunk has <= 1000 repositories
func fetchRepositoriesWithSplitting(ctx context.Context, client *githubclient.GitHubClient, baseQuery string, startingDate, endingDate time.Time) ([]Repository, error) {
	searchQuery := baseQuery + " created:" + startingDate.Format(time.RFC3339) + ".." + endingDate.Format(time.RFC3339)
	repoCount, err := getRepositoryCount(ctx, client, searchQuery)
	if err != nil {
		return nil, err
	}
	if repoCount <= 1000 {
		fmt.Printf("Repository count (%d) for date range %s to %s is less than 1000, fetching all repositories...\n", repoCount, startingDate.Format("2006-01-02"), endingDate.Format("2006-01-02"))
		return fetchRepositories(ctx, client, searchQuery)
	}

	fmt.Printf("Repository count (%d) for date range %s to %s exceeds 1000, splitting date range...\n", repoCount, startingDate.Format("2006-01-02"), endingDate.Format("2006-01-02"))
	midDate := startingDate.Add(endingDate.Sub(startingDate) / 2)
	firstHalf, err := fetchRepositoriesWithSplitting(ctx, client, baseQuery, startingDate, midDate)
	if err != nil {
		return nil, err
	}
	secondHalf, err := fetchRepositoriesWithSplitting(ctx, client, baseQuery, midDate, endingDate)
	if err != nil {
		return nil, err
	}
	allRepos := append(firstHalf, secondHalf...)
	return allRepos, nil
}

// fetchRepositories fetches all repositories for a given query and handles pagination
func fetchRepositories(ctx context.Context, client *githubclient.GitHubClient, query string) ([]Repository, error) {
	var allRepos []Repository
	var after *githubv4.String

	for {
		repos, hasNextPage, endCursor, err := fetchRepositoryPage(ctx, client, query, after)
		if err != nil {
			return nil, err
		}

		allRepos = append(allRepos, repos...)

		if !hasNextPage {
			break
		}

		after = &endCursor
	}

	return allRepos, nil
}

// getRepositoryCount gets the total number of repositories for a query
func getRepositoryCount(ctx context.Context, client *githubclient.GitHubClient, query string) (int, error) {
	var queryStruct struct {
		RateLimit githubclient.RateLimit `graphql:"rateLimit"`
		Search    struct {
			RepositoryCount int
		} `graphql:"search(query: $query, type: REPOSITORY, first: 1)"`
	}

	variables := map[string]interface{}{
		"query": githubv4.String(query),
	}

	err := client.Query(ctx, &queryStruct, variables)
	if err != nil {
		return 0, err
	}

	return queryStruct.Search.RepositoryCount, nil
}

// fetchRepositoryPage fetches a single page of repositories
func fetchRepositoryPage(ctx context.Context, client *githubclient.GitHubClient, query string, after *githubv4.String) ([]Repository, bool, githubv4.String, error) {
	var queryStruct struct {
		RateLimit githubclient.RateLimit `graphql:"rateLimit"`
		Search    struct {
			RepositoryCount int
			PageInfo        struct {
				EndCursor   githubv4.String
				HasNextPage bool
			}
			Edges []struct {
				Node struct {
					Repo Repository `graphql:"... on Repository"`
				}
			}
		} `graphql:"search(query: $query, type: REPOSITORY, first: 100, after: $after)"`
	}

	variables := map[string]interface{}{
		"query": githubv4.String(query),
		"after": after,
	}

	err := client.Query(ctx, &queryStruct, variables)
	if err != nil {
		return nil, false, "", err
	}

	var repos []Repository
	for _, edge := range queryStruct.Search.Edges {
		if !edge.Node.Repo.IsEmpty {
			repos = append(repos, edge.Node.Repo)
		}
	}

	return repos, queryStruct.Search.PageInfo.HasNextPage, queryStruct.Search.PageInfo.EndCursor, nil
}
