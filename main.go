package main

import (
	"context"
	"find-gh-poc/pkg/extract"
	"find-gh-poc/pkg/githubclient"
	"find-gh-poc/pkg/readme"
	"find-gh-poc/pkg/search"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/schollz/progressbar/v3"
)

func run(ctx context.Context, client *githubclient.GitHubClient, query string, outputFile string) error {
	fmt.Println("Fetching repositories...")
	repos, err := search.SearchRepositories(ctx, client, query)
	if err != nil {
		return fmt.Errorf("failed to fetch repositories: %w", err)
	}
	if len(repos) == 0 {
		return fmt.Errorf("no repositories found for query: %s", query)
	}
	fmt.Printf("Found %d repositories\n", len(repos))

	bar := progressbar.NewOptions(len(repos),
		progressbar.OptionSetDescription("Processing repositories..."),
		progressbar.OptionSetItsString("repositories"),
		progressbar.OptionShowIts(),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
	)

	cveExtractor := extract.NewCVEExtractor()
	allRepoCVEs := make(map[string]map[string]bool) // repoURL -> cveID -> true
	const batchSize = 10
	for i := 0; i < len(repos); i += batchSize {
		end := i + batchSize
		if end > len(repos) {
			end = len(repos)
		}
		batch := repos[i:end]

		// If we have a full batch (10 repos), use batch processing
		if len(batch) == batchSize {
			for _, repo := range batch {
				if _, exists := allRepoCVEs[repo.Url]; !exists {
					allRepoCVEs[repo.Url] = make(map[string]bool)
				}
				repoCVEs := cveExtractor.ExtractCVEsFromRepository(repo)
				for _, cve := range repoCVEs {
					allRepoCVEs[repo.Url][cve] = true
				}
			}

			batchReadmes, err := readme.FetchReadmeBatch(ctx, client, batch)
			if err != nil {
				fmt.Printf("Warning: Failed to fetch README batch: %v\n", err)
			} else {
				for _, repo := range batch {
					readme, exists := batchReadmes[repo.Url]
					if !exists {
						readme = ""
					}
					repoCVEs := cveExtractor.ExtractCVEsFromReadme(readme)
					for _, cve := range repoCVEs {
						allRepoCVEs[repo.Url][cve] = true
					}
				}
			}
		} else {
			// Handle remaining repositories individually
			for _, repo := range batch {
				if _, exists := allRepoCVEs[repo.Url]; !exists {
					allRepoCVEs[repo.Url] = make(map[string]bool)
				}
				repoCVEs := cveExtractor.ExtractCVEsFromRepository(repo)
				for _, cve := range repoCVEs {
					allRepoCVEs[repo.Url][cve] = true
				}
				individualReadme, err := readme.FetchSingleReadme(ctx, client, repo)
				if err != nil {
					fmt.Printf("Warning: Failed to fetch README for %s: %v\n", repo.Url, err)
				} else {
					repoCVEs := cveExtractor.ExtractCVEsFromReadme(individualReadme)
					for _, cve := range repoCVEs {
						allRepoCVEs[repo.Url][cve] = true
					}
				}
			}
		}
		bar.Add(len(batch))
	}

	results := make(map[string][]string)
	for repoURL, cveIDs := range allRepoCVEs {
		for cveID := range cveIDs {
			if _, exists := results[cveID]; !exists {
				results[cveID] = make([]string, 0)
			}
			results[cveID] = append(results[cveID], repoURL)
		}
	}

	output, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("couldn't create output file: %w", err)
	}
	defer output.Close()

	for cveID, repoURLs := range results {
		for _, repoURL := range repoURLs {
			_, _ = io.WriteString(output, cveID+" - "+repoURL+"\n")
		}
	}
	return nil
}

func main() {
	token := flag.String("token-string", "", "Github token")
	tokenFile := flag.String("token-file", "", "File to read Github token from")
	query := flag.String("query-string", "", "GraphQL search query")
	queryFile := flag.String("query-file", "", "File to read GraphQL search query from")
	outputFile := flag.String("o", "", "Output file name")
	flag.Parse()

	if (*token == "" && *tokenFile == "") || *outputFile == "" {
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

		tokenData, err := io.ReadAll(file)
		if err != nil {
			fmt.Println("Couldn't read from token file!")
			os.Exit(1)
		}

		githubToken = string(tokenData)
	} else {
		githubToken = *token
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		signalChannel := make(chan os.Signal, 1)
		signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
		<-signalChannel
		fmt.Println("\nProgram interrupted, exiting...")
		cancel()
	}()

	searchQuery := *query
	if searchQuery == "" {
		file, err := os.Open(*queryFile)
		if err != nil {
			fmt.Println("Couldn't open file to read query!")
			os.Exit(1)
		}
		defer file.Close()

		queryData, err := io.ReadAll(file)
		if err != nil {
			fmt.Println("Couldn't read from query file!")
			os.Exit(1)
		}

		searchQuery = strings.Trim(string(queryData), " \n\r\t")
	}

	searchQuery += " in:readme in:description in:name"

	client := githubclient.NewGitHubClient(githubToken)
	err := run(ctx, client, searchQuery, *outputFile)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
