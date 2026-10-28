package images

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// TagInfo is a tag in a repository: the image it points to, and when it was
// pushed, when the registry says (ECR does; the registry API doesn't).
type TagInfo struct {
	Tag      string    `json:"tag"`
	Digest   string    `json:"digest,omitempty"`
	PushedAt time.Time `json:"pushed_at,omitzero"`
}

// ErrListingRefused means the registry doesn't let the login list its
// repositories, as Docker Hub and GHCR never do: the repository's name has
// to be typed instead.
var ErrListingRefused = errors.New("the registry doesn't list its repositories for this login; type the repository's name instead")

// maxListed caps how many repositories or tags one listing reads.
const maxListed = 10000

// Repositories lists a registry's repositories with the registry API's
// catalog.
func (c *Client) Repositories(ctx context.Context, registry string) ([]string, error) {
	var names []string
	address := fmt.Sprintf("%s://%s/v2/_catalog?n=1000", c.Scheme, registry)
	for address != "" && len(names) < maxListed {
		var page struct {
			Repositories []string `json:"repositories"`
		}
		next, err := c.getJSON(ctx, address, registry, registry, "registry:catalog:*", &page)
		if errors.Is(err, ErrUnauthorized) || (err != nil && strings.Contains(err.Error(), "not found in the registry")) {
			return nil, fmt.Errorf("%s: %w", registry, ErrListingRefused)
		}
		if err != nil {
			return nil, err
		}
		names = append(names, page.Repositories...)
		address = next
	}
	sort.Strings(names)
	return names, nil
}

// Tags lists a repository's tags with the registry API.
func (c *Client) Tags(ctx context.Context, registry, repository string) ([]TagInfo, error) {
	var tags []TagInfo
	address := fmt.Sprintf("%s://%s/v2/%s/tags/list?n=1000", c.Scheme, registry, repository)
	for address != "" && len(tags) < maxListed {
		var page struct {
			Tags []string `json:"tags"`
		}
		next, err := c.getJSON(ctx, address, registry, registry+"/"+repository, "repository:"+repository+":pull", &page)
		if err != nil {
			return nil, err
		}
		for _, tag := range page.Tags {
			tags = append(tags, TagInfo{Tag: tag})
		}
		address = next
	}
	return tags, nil
}

// getJSON reads one page of a registry listing, and returns the next page's
// address from its Link header, if there is one.
func (c *Client) getJSON(ctx context.Context, address, registry, what, scope string, into any) (string, error) {
	response, err := c.send(ctx, "GET", address, registry, what, scope, "application/json")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<20)).Decode(into); err != nil {
		return "", fmt.Errorf("%s: unreadable listing: %w", what, err)
	}
	return nextPage(address, response.Header.Get("Link")), nil
}

var linkNext = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="?next"?`)

// nextPage resolves a Link header's next page against the current address,
// staying on the same host.
func nextPage(current, link string) string {
	match := linkNext.FindStringSubmatch(link)
	if match == nil {
		return ""
	}
	base, err := url.Parse(current)
	if err != nil {
		return ""
	}
	next, err := base.Parse(match[1])
	if err != nil || next.Host != base.Host {
		return ""
	}
	return next.String()
}

// MatchTags returns the tags pattern matches, newest first: by push time
// where the registry gave one, then in natural order, so v1.10 comes before
// v1.9. An empty pattern matches every tag.
func MatchTags(tags []TagInfo, pattern string) ([]TagInfo, error) {
	var match *regexp.Regexp
	if pattern != "" {
		var err error
		if match, err = CompileTagPattern(pattern); err != nil {
			return nil, err
		}
	}
	matched := make([]TagInfo, 0, len(tags))
	for _, tag := range tags {
		if match == nil || match.MatchString(tag.Tag) {
			matched = append(matched, tag)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		a, b := matched[i], matched[j]
		if !a.PushedAt.Equal(b.PushedAt) {
			return a.PushedAt.After(b.PushedAt)
		}
		return naturalLess(b.Tag, a.Tag)
	})
	return matched, nil
}

// CompileTagPattern checks a tag pattern, a Go (RE2) regular expression.
func CompileTagPattern(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > 256 {
		return nil, errors.New("the tag pattern is longer than 256 characters")
	}
	match, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("the tag pattern isn't a valid regular expression: %v", err)
	}
	return match, nil
}

// naturalLess compares tags with runs of digits as numbers: 1.9 < 1.10.
func naturalLess(a, b string) bool {
	for a != "" && b != "" {
		aDigits, bDigits := leadingDigits(a), leadingDigits(b)
		if aDigits != "" && bDigits != "" {
			aNumber, bNumber := strings.TrimLeft(aDigits, "0"), strings.TrimLeft(bDigits, "0")
			if len(aNumber) != len(bNumber) {
				return len(aNumber) < len(bNumber)
			}
			if aNumber != bNumber {
				return aNumber < bNumber
			}
			a, b = a[len(aDigits):], b[len(bDigits):]
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func leadingDigits(text string) string {
	end := 0
	for end < len(text) && text[end] >= '0' && text[end] <= '9' {
		end++
	}
	return text[:end]
}
