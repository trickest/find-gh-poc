package readme

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"find-gh-poc/pkg/githubclient"
	"find-gh-poc/pkg/search"

	"github.com/shurcooL/githubv4"
)

type RepositoryReadmeQuery struct {
	Object struct {
		Blob struct {
			Text string
		} `graphql:"... on Blob"`
	} `graphql:"object(expression: \"HEAD:README.md\")"`
}

// fetchReadmeBatch fetches README files for multiple repositories in a single GraphQL query
func FetchReadmeBatch(ctx context.Context, client *githubclient.GitHubClient, repos []search.Repository) (map[string]string, error) {
	if len(repos) == 0 {
		return make(map[string]string), nil
	}

	// Hacky optimization to get the readme for 10 repos at a time
	// Probably not the best way to do this
	var queryStruct struct {
		RateLimit githubclient.RateLimit `graphql:"rateLimit"`

		Repo1  RepositoryReadmeQuery `graphql:"repo1: repository(owner: $owner1, name: $name1)"`
		Repo2  RepositoryReadmeQuery `graphql:"repo2: repository(owner: $owner2, name: $name2)"`
		Repo3  RepositoryReadmeQuery `graphql:"repo3: repository(owner: $owner3, name: $name3)"`
		Repo4  RepositoryReadmeQuery `graphql:"repo4: repository(owner: $owner4, name: $name4)"`
		Repo5  RepositoryReadmeQuery `graphql:"repo5: repository(owner: $owner5, name: $name5)"`
		Repo6  RepositoryReadmeQuery `graphql:"repo6: repository(owner: $owner6, name: $name6)"`
		Repo7  RepositoryReadmeQuery `graphql:"repo7: repository(owner: $owner7, name: $name7)"`
		Repo8  RepositoryReadmeQuery `graphql:"repo8: repository(owner: $owner8, name: $name8)"`
		Repo9  RepositoryReadmeQuery `graphql:"repo9: repository(owner: $owner9, name: $name9)"`
		Repo10 RepositoryReadmeQuery `graphql:"repo10: repository(owner: $owner10, name: $name10)"`
	}

	variables := make(map[string]interface{})
	repoMapping := make(map[string]string)

	for i, repo := range repos {
		parts := strings.Split(repo.Url, "/")
		if len(parts) != 5 {
			continue
		}
		owner := strings.TrimSpace(parts[3])
		name := strings.TrimSpace(parts[4])

		variables[fmt.Sprintf("owner%d", i+1)] = githubv4.String(owner)
		variables[fmt.Sprintf("name%d", i+1)] = githubv4.String(name)
		repoMapping[repo.Url] = fmt.Sprintf("Repo%d", i+1)
	}

	err := client.Query(ctx, &queryStruct, variables)
	if err != nil {
		return nil, err
	}

	readmes := make(map[string]string)
	queryStructValue := reflect.ValueOf(queryStruct)

	for repoURL, fieldName := range repoMapping {
		field := queryStructValue.FieldByName(fieldName)
		if !field.IsValid() {
			readmes[repoURL] = ""
			continue
		}

		objectField := field.FieldByName("Object")
		if !objectField.IsValid() {
			readmes[repoURL] = ""
			continue
		}

		blobField := objectField.FieldByName("Blob")
		if !blobField.IsValid() {
			readmes[repoURL] = ""
			continue
		}

		textField := blobField.FieldByName("Text")
		if textField.IsValid() {
			readmes[repoURL] = textField.String()
		} else {
			readmes[repoURL] = ""
		}

	}

	return readmes, nil
}

// FetchSingleReadme fetches README file for a single repository
func FetchSingleReadme(ctx context.Context, client *githubclient.GitHubClient, repo search.Repository) (string, error) {
	parts := strings.Split(repo.Url, "/")
	if len(parts) != 5 {
		return "", fmt.Errorf("invalid repository URL: %s", repo.Url)
	}
	owner := strings.TrimSpace(parts[3])
	name := strings.TrimSpace(parts[4])

	var queryStruct struct {
		RateLimit  githubclient.RateLimit `graphql:"rateLimit"`
		Repository RepositoryReadmeQuery  `graphql:"repository(owner: $owner, name: $name)"`
	}

	variables := map[string]interface{}{
		"owner": githubv4.String(owner),
		"name":  githubv4.String(name),
	}

	err := client.Query(ctx, &queryStruct, variables)
	if err != nil {
		return "", fmt.Errorf("failed to fetch README for %s: %w", repo.Url, err)
	}

	return queryStruct.Repository.Object.Blob.Text, nil
}
