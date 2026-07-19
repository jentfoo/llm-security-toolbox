package mutate

import (
	"net/url"
	"strings"

	"github.com/go-analyze/bulk"
)

// Query applies remove-then-set edits to a raw query string without parsing,
// preserving parameter order and percent-encoding. remove holds param names;
// set holds "key=value" entries.
func Query(query string, remove, set []string) string {
	parts := strings.Split(query, "&")
	if len(parts) == 1 && parts[0] == "" {
		parts = nil
	}

	if len(remove) > 0 {
		removeSet := bulk.SliceToSet(remove)
		parts = bulk.SliceFilterInPlace(func(p string) bool {
			key, _, _ := strings.Cut(p, "=")
			for rk := range removeSet {
				if keysMatch(key, rk) {
					return false
				}
			}
			return true
		}, parts)
	}

	for _, entry := range set {
		key, _, _ := strings.Cut(entry, "=")
		var replaced bool
		for i, p := range parts {
			existingKey, _, _ := strings.Cut(p, "=")
			if keysMatch(existingKey, key) {
				parts[i] = entry
				replaced = true
				break
			}
		}
		if !replaced {
			parts = append(parts, entry)
		}
	}

	return strings.Join(parts, "&")
}

// keysMatch reports whether two query keys refer to the same parameter,
// comparing literally then via percent-decoding either side.
func keysMatch(queryKey, paramKey string) bool {
	if queryKey == paramKey {
		return true
	} else if decoded, err := url.QueryUnescape(queryKey); err == nil && decoded != queryKey && decoded == paramKey {
		return true
	} else if decoded, err = url.QueryUnescape(paramKey); err == nil && decoded != paramKey && queryKey == decoded {
		return true
	}
	return false
}
