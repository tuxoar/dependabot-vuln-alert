package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultBaseURL    = "https://api.github.com"
	defaultWebURL     = "https://github.com"
	defaultState      = "open"
	maxAlertsPerRepo  = 50
	maxReposInMessage = 25
	maxSlackBlocks    = 50
	slackChunkLimit   = 2900
	perPage           = 100
	httpTimeout       = 30 * time.Second
)

type severity string

const (
	sevCritical severity = "critical"
	sevHigh     severity = "high"
	sevMedium   severity = "medium"
	sevLow      severity = "low"
)

var severityRank = map[severity]int{
	sevCritical: 0,
	sevHigh:     1,
	sevMedium:   2,
	sevLow:      3,
}

var severityIcon = map[severity]string{
	sevCritical: ":fire:",
	sevHigh:     ":warning:",
	sevMedium:   ":large_yellow_circle:",
	sevLow:      ":white_circle:",
}

// GitHub API types

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type SecurityAdvisory struct {
	GHSAID   string `json:"ghsa_id"`
	Summary  string `json:"summary"`
	Severity string `json:"severity"`
}

type SecurityVulnerability struct {
	Package                Package `json:"package"`
	Severity               string  `json:"severity"`
	VulnerableVersionRange string  `json:"vulnerable_version_range"`
}

type Dependency struct {
	Package      Package `json:"package"`
	ManifestPath string  `json:"manifest_path"`
}

type DependabotAlert struct {
	Number                int                   `json:"number"`
	State                 string                `json:"state"`
	HTMLURL               string                `json:"html_url"`
	SecurityAdvisory      SecurityAdvisory      `json:"security_advisory"`
	SecurityVulnerability SecurityVulnerability  `json:"security_vulnerability"`
	Dependency            Dependency             `json:"dependency"`
	CreatedAt             time.Time              `json:"created_at"`
}

func (a DependabotAlert) Severity() severity {
	if s := a.SecurityAdvisory.Severity; s != "" {
		return severity(strings.ToLower(s))
	}
	return severity(strings.ToLower(a.SecurityVulnerability.Severity))
}

func (a DependabotAlert) PackageName() string {
	if n := a.Dependency.Package.Name; n != "" {
		return n
	}
	return a.SecurityVulnerability.Package.Name
}

type OrgDependabotAlert struct {
	DependabotAlert
	Repository Repository `json:"repository"`
}

type Repository struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
}

// Configuration

type Config struct {
	GitHubToken     string
	AppID           int64
	AppKeyPath      string
	AppKeyData      string // PEM contents directly (alternative to AppKeyPath)
	InstallID       int64
	GitHubBaseURL   string
	Org             string
	User            string
	Repos           []string
	Severity        []string
	State           string
	SlackWebhookURL string
}

func (c Config) Owner() string {
	if c.Org != "" {
		return c.Org
	}
	return c.User
}

func (c Config) IsOrg() bool { return c.Org != "" }

func (c Config) IsAppAuth() bool { return c.AppID != 0 }

func (c Config) WebURL() string {
	if c.GitHubBaseURL != defaultBaseURL {
		return strings.TrimSuffix(c.GitHubBaseURL, "/api/v3")
	}
	return defaultWebURL
}

func (c Config) SeverityFilter() map[severity]bool {
	m := make(map[severity]bool, len(c.Severity))
	for _, s := range c.Severity {
		m[severity(strings.TrimSpace(s))] = true
	}
	return m
}

func loadConfig() (Config, error) {
	cfg := Config{
		GitHubToken:     os.Getenv("GITHUB_TOKEN"),
		AppKeyPath:      os.Getenv("GITHUB_APP_KEY_PATH"),
		AppKeyData:      os.Getenv("GITHUB_APP_KEY"),
		GitHubBaseURL:   os.Getenv("GITHUB_BASE_URL"),
		Org:             os.Getenv("GITHUB_ORG"),
		User:            os.Getenv("GITHUB_USER"),
		State:           os.Getenv("ALERT_STATE"),
		SlackWebhookURL: os.Getenv("SLACK_WEBHOOK_URL"),
	}

	if v := os.Getenv("GITHUB_APP_ID"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return cfg, fmt.Errorf("invalid GITHUB_APP_ID: %w", err)
		}
		cfg.AppID = id
	}
	if v := os.Getenv("GITHUB_INSTALL_ID"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return cfg, fmt.Errorf("invalid GITHUB_INSTALL_ID: %w", err)
		}
		cfg.InstallID = id
	}

	if cfg.GitHubBaseURL == "" {
		cfg.GitHubBaseURL = defaultBaseURL
	}
	cfg.GitHubBaseURL = strings.TrimRight(cfg.GitHubBaseURL, "/")

	if cfg.State == "" {
		cfg.State = defaultState
	}

	if v := os.Getenv("GITHUB_REPOS"); v != "" {
		for _, r := range strings.Split(v, ",") {
			if t := strings.TrimSpace(r); t != "" {
				cfg.Repos = append(cfg.Repos, t)
			}
		}
	}

	if v := os.Getenv("ALERT_SEVERITY"); v != "" {
		cfg.Severity = strings.Split(strings.ToLower(v), ",")
	} else {
		cfg.Severity = []string{"critical", "high", "medium"}
	}

	if cfg.Org == "" && cfg.User == "" {
		return cfg, fmt.Errorf("set GITHUB_ORG or GITHUB_USER")
	}
	if cfg.SlackWebhookURL == "" {
		return cfg, fmt.Errorf("SLACK_WEBHOOK_URL is required")
	}
	if cfg.GitHubToken == "" && !cfg.IsAppAuth() {
		return cfg, fmt.Errorf("set GITHUB_TOKEN or GITHUB_APP_ID + GITHUB_APP_KEY_PATH")
	}

	return cfg, nil
}

// HTTP client

type GitHubClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewGitHubClient(baseURL, token string) *GitHubClient {
	return &GitHubClient{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Timeout: httpTimeout},
	}
}

func (c *GitHubClient) request(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.http.Do(req)
}

// fetchPage performs a single GET, reads and closes the body, and returns the
// raw bytes along with the status code and the next-page path (empty if none).
func (c *GitHubClient) fetchPage(ctx context.Context, path string) ([]byte, int, string, error) {
	resp, err := c.request(ctx, "GET", path, nil)
	if err != nil {
		return nil, 0, "", err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var next string
	if link := parseNextLink(resp.Header.Get("Link")); link != "" {
		next = strings.TrimPrefix(link, c.baseURL)
	}
	return body, resp.StatusCode, next, nil
}

func parseNextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		if start, end := strings.Index(part, "<"), strings.Index(part, ">"); start >= 0 && end > start {
			return part[start+1 : end]
		}
	}
	return ""
}

// paginate walks all pages of a GitHub list endpoint that returns a JSON array.
func paginate[T any](ctx context.Context, c *GitHubClient, path string) ([]T, int, error) {
	var all []T
	for path != "" {
		body, status, next, err := c.fetchPage(ctx, path)
		if err != nil {
			return nil, 0, err
		}
		if status != http.StatusOK {
			return nil, status, fmt.Errorf("%d: %s", status, body)
		}
		var page []T
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, 0, fmt.Errorf("decoding response: %w", err)
		}
		if len(page) == 0 {
			break
		}
		all = append(all, page...)
		path = next
	}
	return all, http.StatusOK, nil
}

// paginateWrapped walks pages where results are nested under a JSON key.
func paginateWrapped[T any](ctx context.Context, c *GitHubClient, path, key string) ([]T, error) {
	var all []T
	for path != "" {
		body, status, next, err := c.fetchPage(ctx, path)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("%d: %s", status, body)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("decoding response: %w", err)
		}
		var page []T
		if err := json.Unmarshal(raw[key], &page); err != nil {
			return nil, fmt.Errorf("decoding %s: %w", key, err)
		}
		if len(page) == 0 {
			break
		}
		all = append(all, page...)
		path = next
	}
	return all, nil
}

// Repository listing

func (c *GitHubClient) ListOrgRepos(ctx context.Context, org string) ([]Repository, error) {
	repos, _, err := paginate[Repository](ctx, c, fmt.Sprintf("/orgs/%s/repos?per_page=%d&type=all", org, perPage))
	return repos, err
}

func (c *GitHubClient) ListUserRepos(ctx context.Context) ([]Repository, error) {
	repos, _, err := paginate[Repository](ctx, c, fmt.Sprintf("/user/repos?per_page=%d&affiliation=owner,collaborator,organization_member", perPage))
	return repos, err
}

func (c *GitHubClient) ListInstallationRepos(ctx context.Context) ([]Repository, error) {
	return paginateWrapped[Repository](ctx, c, fmt.Sprintf("/installation/repositories?per_page=%d", perPage), "repositories")
}

// Dependabot alerts

func (c *GitHubClient) ListRepoDependabotAlerts(ctx context.Context, owner, repo, state string) ([]DependabotAlert, error) {
	alerts, status, err := paginate[DependabotAlert](ctx, c, fmt.Sprintf("/repos/%s/%s/dependabot/alerts?state=%s&per_page=%d", owner, repo, state, perPage))
	if status == http.StatusNotFound {
		return nil, nil
	}
	return alerts, err
}

func (c *GitHubClient) ListOrgDependabotAlerts(ctx context.Context, org, state string) ([]OrgDependabotAlert, error) {
	alerts, _, err := paginate[OrgDependabotAlert](ctx, c, fmt.Sprintf("/orgs/%s/dependabot/alerts?state=%s&per_page=%d", org, state, perPage))
	return alerts, err
}

// GitHub App authentication

func parseRSAKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key data")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	return key, nil
}

func loadKeyData(cfg Config) ([]byte, error) {
	if cfg.AppKeyData != "" {
		return []byte(cfg.AppKeyData), nil
	}
	if cfg.AppKeyPath != "" {
		return os.ReadFile(cfg.AppKeyPath)
	}
	return nil, fmt.Errorf("set GITHUB_APP_KEY or GITHUB_APP_KEY_PATH")
}

func generateAppJWT(appID int64, keyPEM []byte) (string, error) {
	key, err := parseRSAKey(keyPEM)
	if err != nil {
		return "", err
	}
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		Issuer:    strconv.FormatInt(appID, 10),
	})
	return token.SignedString(key)
}

func (c *GitHubClient) createInstallationToken(ctx context.Context, installID int64) (string, error) {
	resp, err := c.request(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", installID), nil)
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("creating installation token: %d %s", resp.StatusCode, body)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	return tok.Token, nil
}

func (c *GitHubClient) findInstallation(ctx context.Context, account string) (int64, error) {
	resp, err := c.request(ctx, "GET", "/app/installations", nil)
	if err != nil {
		return 0, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var installations []struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	if err := json.Unmarshal(body, &installations); err != nil {
		return 0, err
	}
	for _, inst := range installations {
		if strings.EqualFold(inst.Account.Login, account) {
			return inst.ID, nil
		}
	}
	return 0, fmt.Errorf("no installation found for %q", account)
}

func authenticateApp(ctx context.Context, cfg Config) (*GitHubClient, error) {
	log.Println("Authenticating as GitHub App...")

	keyPEM, err := loadKeyData(cfg)
	if err != nil {
		return nil, err
	}

	jwtToken, err := generateAppJWT(cfg.AppID, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("generating JWT: %w", err)
	}

	appClient := NewGitHubClient(cfg.GitHubBaseURL, jwtToken)

	installID := cfg.InstallID
	if installID == 0 {
		installID, err = appClient.findInstallation(ctx, cfg.Owner())
		if err != nil {
			return nil, fmt.Errorf("finding installation: %w", err)
		}
		log.Printf("Found installation %d for %s", installID, cfg.Owner())
	}

	token, err := appClient.createInstallationToken(ctx, installID)
	if err != nil {
		return nil, fmt.Errorf("creating installation token: %w", err)
	}
	log.Println("Authenticated with installation token")

	return NewGitHubClient(cfg.GitHubBaseURL, token), nil
}

// Alert collection

func collectAlerts(ctx context.Context, client *GitHubClient, cfg Config) (map[string][]DependabotAlert, error) {
	owner := cfg.Owner()

	if len(cfg.Repos) > 0 {
		return collectFromExplicitRepos(ctx, client, owner, cfg.Repos, cfg.State)
	}

	repos, err := listRepos(ctx, client, cfg)
	if err != nil {
		return nil, err
	}
	return scanRepos(ctx, client, owner, repos, cfg.State)
}

func listRepos(ctx context.Context, client *GitHubClient, cfg Config) ([]Repository, error) {
	switch {
	case cfg.IsOrg():
		log.Printf("Listing repos for org %s...", cfg.Owner())
		return client.ListOrgRepos(ctx, cfg.Owner())
	case cfg.IsAppAuth():
		log.Printf("Listing installation repos for %s...", cfg.Owner())
		return client.ListInstallationRepos(ctx)
	default:
		log.Printf("Listing repos for user %s...", cfg.Owner())
		return client.ListUserRepos(ctx)
	}
}

func collectFromExplicitRepos(ctx context.Context, client *GitHubClient, owner string, repos []string, state string) (map[string][]DependabotAlert, error) {
	log.Printf("Fetching alerts for %d specified repos...", len(repos))
	result := make(map[string][]DependabotAlert, len(repos))

	for _, repo := range repos {
		repoOwner, repoName := parseRepo(owner, repo)
		fullName := repoOwner + "/" + repoName
		alerts, err := client.ListRepoDependabotAlerts(ctx, repoOwner, repoName, state)
		if err != nil {
			log.Printf("  WARN: %s: %v", fullName, err)
			continue
		}
		if len(alerts) > 0 {
			result[fullName] = alerts
		}
	}
	return result, nil
}

func parseRepo(defaultOwner, repo string) (owner, name string) {
	if i := strings.IndexByte(repo, '/'); i >= 0 {
		return repo[:i], repo[i+1:]
	}
	return defaultOwner, repo
}

func scanRepos(ctx context.Context, client *GitHubClient, owner string, repos []Repository, state string) (map[string][]DependabotAlert, error) {
	log.Printf("Checking %d repos for alerts...", len(repos))
	result := make(map[string][]DependabotAlert)

	for _, repo := range repos {
		alerts, err := client.ListRepoDependabotAlerts(ctx, owner, repo.Name, state)
		if err != nil {
			log.Printf("  WARN: %s: %v", repo.FullName, err)
			continue
		}
		if len(alerts) > 0 {
			result[repo.FullName] = alerts
		}
	}
	return result, nil
}

// Summary building

type RepoSummary struct {
	Repo     string
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Alerts   []DependabotAlert
}

func buildSummaries(alertsByRepo map[string][]DependabotAlert, filter map[severity]bool) []RepoSummary {
	summaries := make([]RepoSummary, 0, len(alertsByRepo))

	for repo, alerts := range alertsByRepo {
		s := RepoSummary{Repo: repo}
		for _, a := range alerts {
			sev := a.Severity()
			if len(filter) > 0 && !filter[sev] {
				continue
			}
			s.Alerts = append(s.Alerts, a)
			switch sev {
			case sevCritical:
				s.Critical++
			case sevHigh:
				s.High++
			case sevMedium:
				s.Medium++
			case sevLow:
				s.Low++
			}
		}
		if len(s.Alerts) == 0 {
			continue
		}
		s.Total = len(s.Alerts)
		sort.Slice(s.Alerts, func(i, j int) bool {
			return severityRank[s.Alerts[i].Severity()] < severityRank[s.Alerts[j].Severity()]
		})
		summaries = append(summaries, s)
	}

	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].Critical != summaries[j].Critical {
			return summaries[i].Critical > summaries[j].Critical
		}
		return summaries[i].Total > summaries[j].Total
	})
	return summaries
}

// Slack output

type SlackBlock struct {
	Type string     `json:"type"`
	Text *SlackText `json:"text,omitempty"`
}

type SlackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type SlackMessage struct {
	Text   string       `json:"text"`
	Blocks []SlackBlock `json:"blocks"`
}

func mrkdwn(text string) SlackBlock {
	return SlackBlock{Type: "section", Text: &SlackText{Type: "mrkdwn", Text: text}}
}

func divider() SlackBlock {
	return SlackBlock{Type: "divider"}
}

func icon(sev severity) string {
	if s, ok := severityIcon[sev]; ok {
		return s
	}
	return ":white_circle:"
}

type severityCount struct {
	sev   severity
	count int
}

func (s RepoSummary) countsBySeverity() []severityCount {
	all := []severityCount{
		{sevCritical, s.Critical},
		{sevHigh, s.High},
		{sevMedium, s.Medium},
		{sevLow, s.Low},
	}
	out := make([]severityCount, 0, 4)
	for _, c := range all {
		if c.count > 0 {
			out = append(out, c)
		}
	}
	return out
}

func formatSlackMessage(owner, webURL string, summaries []RepoSummary) SlackMessage {
	if len(summaries) == 0 {
		return SlackMessage{
			Text:   fmt.Sprintf("%s — No open Dependabot alerts!", owner),
			Blocks: []SlackBlock{mrkdwn(fmt.Sprintf(":white_check_mark: *%s* — No open Dependabot alerts!", owner))},
		}
	}

	var totalAlerts, totalCritical, totalHigh int
	for _, s := range summaries {
		totalAlerts += s.Total
		totalCritical += s.Critical
		totalHigh += s.High
	}

	blocks := make([]SlackBlock, 0, maxSlackBlocks)

	header := fmt.Sprintf(":rotating_light: *Dependabot Vulnerability Report — %s*\n_%s_ | *%d* alerts across *%d* repos",
		owner, time.Now().Format("2006-01-02"), totalAlerts, len(summaries))
	if totalCritical > 0 {
		header += fmt.Sprintf(" | :fire: %d critical", totalCritical)
	}
	if totalHigh > 0 {
		header += fmt.Sprintf(" | :warning: %d high", totalHigh)
	}
	blocks = append(blocks, mrkdwn(header), divider())

	for i, s := range summaries {
		if i >= maxReposInMessage {
			blocks = append(blocks, mrkdwn(fmt.Sprintf("_...and %d more repos_", len(summaries)-maxReposInMessage)))
			break
		}

		depURL := fmt.Sprintf("%s/%s/security/dependabot", webURL, s.Repo)
		blocks = append(blocks, mrkdwn(repoHeader(s, depURL)))
		blocks = append(blocks, alertBlocks(s, depURL)...)

		if i < len(summaries)-1 {
			blocks = append(blocks, divider())
		}
	}

	if len(blocks) > maxSlackBlocks {
		blocks = blocks[:maxSlackBlocks]
	}

	return SlackMessage{
		Text:   fmt.Sprintf("Dependabot Report: %d alerts across %d repos", totalAlerts, len(summaries)),
		Blocks: blocks,
	}
}

func repoHeader(s RepoSummary, depURL string) string {
	line := fmt.Sprintf("*<%s|%s>* — %d alerts", depURL, s.Repo, s.Total)

	counts := s.countsBySeverity()
	if len(counts) == 0 {
		return line
	}

	parts := make([]string, 0, len(counts))
	for _, c := range counts {
		parts = append(parts, fmt.Sprintf("%s %d %s", icon(c.sev), c.count, c.sev))
	}
	return line + "\n" + strings.Join(parts, "  |  ")
}

func alertBlocks(s RepoSummary, depURL string) []SlackBlock {
	display := s.Alerts
	truncated := len(display) > maxAlertsPerRepo
	if truncated {
		display = display[:maxAlertsPerRepo]
	}

	var blocks []SlackBlock
	var chunk strings.Builder

	for _, a := range display {
		line := fmt.Sprintf("%s `%s` — %s <%s|#%d>\n",
			icon(a.Severity()), a.PackageName(), a.SecurityAdvisory.Summary, a.HTMLURL, a.Number)

		if chunk.Len()+len(line) > slackChunkLimit {
			blocks = append(blocks, mrkdwn(chunk.String()))
			chunk.Reset()
		}
		chunk.WriteString(line)
	}

	if truncated {
		chunk.WriteString(fmt.Sprintf("_...and %d more — <%s|view all>_\n", len(s.Alerts)-maxAlertsPerRepo, depURL))
	}
	if chunk.Len() > 0 {
		blocks = append(blocks, mrkdwn(chunk.String()))
	}
	return blocks
}

func sendSlack(ctx context.Context, webhookURL string, msg SlackMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return fmt.Errorf("slack request: %w", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack %d: %s", resp.StatusCode, respBody)
	}
	if s := string(respBody); s != "ok" {
		return fmt.Errorf("slack error: %s", s)
	}
	return nil
}

// Entrypoint

func run(ctx context.Context) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	var client *GitHubClient
	if cfg.IsAppAuth() {
		client, err = authenticateApp(ctx, cfg)
		if err != nil {
			return err
		}
	} else {
		client = NewGitHubClient(cfg.GitHubBaseURL, cfg.GitHubToken)
	}

	alertsByRepo, err := collectAlerts(ctx, client, cfg)
	if err != nil {
		return err
	}
	log.Printf("Found alerts in %d repos", len(alertsByRepo))

	summaries := buildSummaries(alertsByRepo, cfg.SeverityFilter())
	msg := formatSlackMessage(cfg.Owner(), cfg.WebURL(), summaries)

	fmt.Println(msg.Text)

	log.Println("Sending to Slack...")
	if err := sendSlack(ctx, cfg.SlackWebhookURL, msg); err != nil {
		return err
	}
	log.Println("Done!")
	return nil
}

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
