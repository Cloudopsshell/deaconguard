package advisory

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"deaconguard/internal/inventory"
	"deaconguard/internal/platform"
)

// Loaders and evaluators for the families added in 0.19.0: AlmaLinux and
// Oracle Linux (OVAL), openSUSE Leap and SUSE Linux Enterprise (SUSE's
// OVAL), and Rocky Linux and Fedora (their repositories' updateinfo).

// FamilyOVALSource is the official OVAL feed of an AlmaLinux, Oracle Linux
// or SUSE release.
func FamilyOVALSource(target platform.Platform) (url, cacheName string, err error) {
	switch target.Family {
	case platform.Alma:
		return fmt.Sprintf("https://security.almalinux.org/oval/org.almalinux.alsa-%d.xml.bz2", target.Major), fmt.Sprintf("almalinux-%d-oval", target.Major), nil
	case platform.Oracle:
		return fmt.Sprintf("https://linux.oracle.com/security/oval/com.oracle.elsa-ol%d.xml.bz2", target.Major), fmt.Sprintf("oracle-%d-oval", target.Major), nil
	case platform.OpenSUSELeap:
		return fmt.Sprintf("https://ftp.suse.com/pub/projects/security/oval/opensuse.leap.%s.xml.gz", target.VersionID), "opensuse-leap-" + target.VersionID + "-oval", nil
	case platform.SLES:
		if target.Major == 15 {
			return fmt.Sprintf("https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.15-sp%d.xml.gz", target.Minor), fmt.Sprintf("sles-15-sp%d-oval", target.Minor), nil
		}
		return fmt.Sprintf("https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.%d.%d.xml.gz", target.Major, target.Minor), fmt.Sprintf("sles-%d.%d-oval", target.Major, target.Minor), nil
	}
	return "", "", fmt.Errorf("no OVAL feed for %s", target.Family)
}

// LoadFamilyOVAL downloads a release's OVAL feed (or reads it from the cache).
func LoadFamilyOVAL(target platform.Platform, client HTTPClient, now time.Time) (Feed, error) {
	url, cacheName, err := FamilyOVALSource(target)
	if err != nil {
		return Feed{}, err
	}
	return LoadFeed(url, cacheName, client, now)
}

// EvaluateFamilyOVAL evaluates a compressed OVAL feed of an AlmaLinux,
// Oracle Linux or SUSE release.
func EvaluateFamilyOVAL(target platform.Platform, compressed []byte, packages []inventory.Package) (FamilyEvaluation, error) {
	stream, err := decompress(compressed)
	if err != nil {
		return FamilyEvaluation{}, err
	}
	var keys []string
	if target.Family == platform.OpenSUSELeap || target.Family == platform.SLES {
		keys = VendorKeys["suse"]
	}
	return evaluateRPMFamilyOVAL(io.LimitReader(stream, maxExpandedOVAL), packages, keys)
}

// decompress reads bzip2, gzip or zstd, as the magic bytes say.
func decompress(data []byte) (io.Reader, error) {
	switch {
	case bytes.HasPrefix(data, []byte("BZh")):
		return bzip2.NewReader(bytes.NewReader(data)), nil
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		return gzip.NewReader(bytes.NewReader(data))
	case bytes.HasPrefix(data, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		decoder, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxExpandedOVAL))
		if err != nil {
			return nil, err
		}
		return decoder.IOReadCloser(), nil
	case bytes.HasPrefix(bytes.TrimSpace(data), []byte("<?xml")):
		return bytes.NewReader(data), nil
	}
	return nil, errors.New("the feed is not bzip2, gzip, zstd or XML")
}

// Architecture is the machine's architecture, from its packages: what
// glibc is built for.
func Architecture(packages []inventory.Package) string {
	for _, item := range packages {
		if item.Name == "glibc" && item.Arch != "" && item.Arch != "noarch" {
			return item.Arch
		}
	}
	counts := map[string]int{}
	for _, item := range packages {
		if item.Arch != "" && item.Arch != "noarch" && item.Arch != "i686" {
			counts[item.Arch]++
		}
	}
	best, most := "x86_64", 0
	for arch, count := range counts {
		if count > most {
			best, most = arch, count
		}
	}
	return best
}

// updateInfoRepositories are the repositories whose updateinfo covers a
// release's packages, with a link to each advisory.
func updateInfoRepositories(target platform.Platform, arch string) ([]string, func(string) string, error) {
	switch target.Family {
	case platform.Rocky:
		base := fmt.Sprintf("https://dl.rockylinux.org/pub/rocky/%d", target.Major)
		return []string{base + "/BaseOS/" + arch + "/os/", base + "/AppStream/" + arch + "/os/"},
			func(id string) string { return "https://errata.rockylinux.org/" + id }, nil
	case platform.Fedora:
		return []string{fmt.Sprintf("https://dl.fedoraproject.org/pub/fedora/linux/updates/%d/Everything/%s/", target.Major, arch)},
			func(id string) string { return "https://bodhi.fedoraproject.org/updates/" + id }, nil
	}
	return nil, nil, fmt.Errorf("no updateinfo for %s", target.Family)
}

// LoadUpdateInfo downloads the updateinfo of each of a release's
// repositories, through their repomd.xml, and evaluates the packages
// against them. metadata describes the first repository's.
func LoadUpdateInfo(target platform.Platform, packages []inventory.Package, client HTTPClient, now time.Time) (DebianEvaluation, FeedMetadata, error) {
	arch := Architecture(packages)
	repositories, advisory, err := updateInfoRepositories(target, arch)
	if err != nil {
		return DebianEvaluation{}, FeedMetadata{}, err
	}
	sources := make([]UpdateInfoSource, 0, len(repositories))
	var metadata FeedMetadata
	for index, repository := range repositories {
		name := fmt.Sprintf("%s-%d-%s-%d", target.Family, target.Major, arch, index)
		index := index
		repomd, err := LoadFeed(repository+"repodata/repomd.xml", name+"-repomd", client, now)
		if err != nil && target.Family == platform.Fedora {
			// An end-of-life Fedora's repositories move to the archive.
			archived := strings.Replace(repository, "https://dl.fedoraproject.org/pub/fedora/", "https://archives.fedoraproject.org/pub/archive/fedora/", 1)
			if repomd, err = LoadFeed(archived+"repodata/repomd.xml", name+"-archive-repomd", client, now); err == nil {
				repository = archived
			}
		}
		if err != nil {
			return DebianEvaluation{}, FeedMetadata{}, err
		}
		location, err := updateInfoLocation(repomd.Data)
		if err != nil {
			return DebianEvaluation{}, FeedMetadata{}, fmt.Errorf("%s: %w", repository, err)
		}
		feed, err := LoadFeed(repository+location, name+"-updateinfo", client, now)
		if err != nil {
			return DebianEvaluation{}, FeedMetadata{}, err
		}
		if index == 0 {
			metadata = feed.Metadata
		}
		stream, err := decompress(feed.Data)
		if err != nil {
			return DebianEvaluation{}, FeedMetadata{}, err
		}
		sources = append(sources, UpdateInfoSource{Data: io.LimitReader(stream, maxExpandedOVAL), Advisory: advisory})
	}
	evaluation, err := evaluateUpdateInfo(sources, packages)
	return evaluation, metadata, err
}

// updateInfoLocation finds updateinfo's file in a repository's repomd.xml.
func updateInfoLocation(repomd []byte) (string, error) {
	var document struct {
		Data []struct {
			Type     string `xml:"type,attr"`
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
		} `xml:"data"`
	}
	if err := xml.Unmarshal(repomd, &document); err != nil {
		return "", fmt.Errorf("read repomd.xml: %w", err)
	}
	for _, data := range document.Data {
		if data.Type == "updateinfo" && data.Location.Href != "" && !strings.Contains(data.Location.Href, "..") {
			return data.Location.Href, nil
		}
	}
	return "", errors.New("the repository publishes no updateinfo")
}
