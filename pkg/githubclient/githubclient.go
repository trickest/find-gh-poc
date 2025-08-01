package githubclient

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

// RateLimit represents GitHub API rate limit information
type RateLimit struct {
	Limit     int
	Remaining int
	Cost      int
	ResetAt   time.Time
}

// GitHubClient handles GitHub API calls with built-in handling of primary and secondary rate limits
type GitHubClient struct {
	client                *githubv4.Client
	lastRateLimit         *RateLimit
	secondaryBackoffDelay time.Duration
	maxSecondaryBackoff   time.Duration
}

// NewGitHubClient creates a new GitHub client with rate limiting
func NewGitHubClient(githubToken string) *GitHubClient {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubToken},
	)
	httpClient := oauth2.NewClient(context.Background(), src)
	githubV4Client := githubv4.NewClient(httpClient)

	return &GitHubClient{client: githubV4Client,
		secondaryBackoffDelay: 1 * time.Minute,
		maxSecondaryBackoff:   10 * time.Minute,
	}
}

// Query executes a GraphQL query with automatic rate limiting and error handling
func (c *GitHubClient) Query(ctx context.Context, query interface{}, variables map[string]interface{}) error {
	c.sleepIfNeeded()
	err := c.client.Query(ctx, query, variables)
	rateLimit := c.extractRateLimitFromQueryResponse(query)
	if rateLimit != nil {
		c.lastRateLimit = rateLimit
	}
	if err != nil {
		handledErr := c.handleError(err)
		if handledErr == nil {
			// Error was handled (e.g., rate limit), retry the query
			return c.Query(ctx, query, variables)
		}
		// Return unhandled errors to caller
		return handledErr
	}

	return nil
}

// extractRateLimitFromQueryResponse extracts the RateLimit field from a query response struct using reflection
func (c *GitHubClient) extractRateLimitFromQueryResponse(query interface{}) *RateLimit {
	queryValue := reflect.ValueOf(query)
	if queryValue.Kind() == reflect.Ptr {
		queryValue = queryValue.Elem()
	}

	rateLimitField := queryValue.FieldByName("RateLimit")
	if rateLimitField.IsValid() && rateLimitField.CanAddr() {
		rateLimit := rateLimitField.Addr().Interface().(*RateLimit)
		return rateLimit
	}
	return nil
}

// sleepIfNeeded checks the last known rate limit and sleeps if needed
// After it returns, it's safe to make a request
func (c *GitHubClient) sleepIfNeeded() {
	if c.lastRateLimit == nil {
		return
	}

	if c.lastRateLimit.Remaining <= 0 {
		untilReset := time.Until(c.lastRateLimit.ResetAt)
		if untilReset > 0 {
			fmt.Printf("Rate limit reached. Waiting %v until reset at %s...\n",
				untilReset, c.lastRateLimit.ResetAt.Format(time.RFC1123))
			time.Sleep(untilReset + 3*time.Second) // buffer
		}
	}
}

// handleError handles known errors (secondary rate limit) and returns nil if it was handled
// otherwise it returns the error to the caller
func (c *GitHubClient) handleError(err error) error {
	if err == nil {
		return nil
	}

	// Handle secondary rate limits with exponential backoff
	// https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28#about-secondary-rate-limits
	if strings.Contains(err.Error(), "secondary rate limit") {
		fmt.Printf("Secondary rate limit hit, waiting %v before retry...\n", c.secondaryBackoffDelay)
		time.Sleep(c.secondaryBackoffDelay)

		c.secondaryBackoffDelay *= 2
		if c.secondaryBackoffDelay > c.maxSecondaryBackoff {
			c.secondaryBackoffDelay = c.maxSecondaryBackoff
		}

		return nil
	}
	return err
}
