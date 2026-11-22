// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// PublicKeyIndexKeyPrefix namespaces search-index keys derived from public
// keys, so a key fingerprint can never collide with an artifact digest, which
// is indexed as "<algorithm>:<hex>".
const PublicKeyIndexKeyPrefix = "publickey:sha256:"

// PublicKeyIndexKey returns the canonical search-index key for a public key:
// the SHA-256 digest of its canonical form, inside the public key namespace.
// Every entry type must use this for keys derived from public keys.
func PublicKeyIndexKey(canonicalKey []byte) string {
	sum := sha256.Sum256(canonicalKey)
	return PublicKeyIndexKeyPrefix + hex.EncodeToString(sum[:])
}

// PublicKeyIndexKeys returns every form under which a public key may have been
// indexed: the canonical PublicKeyIndexKey first, then the historical forms
// written before the key namespace was unified. Entries already indexed under
// a historical form cannot be rewritten, so lookups must try every form.
func PublicKeyIndexKeys(canonicalKey, rawKey []byte) []string {
	canonicalSum := sha256.Sum256(canonicalKey)
	bare := hex.EncodeToString(canonicalSum[:])
	keys := []string{
		PublicKeyIndexKeyPrefix + bare, // canonical form
		bare,                           // legacy: bare hex digest of the canonical key
		"sha256:" + bare,               // legacy: digest of the canonical key in the artifact-digest namespace
	}
	// legacy: bare hex digest of the raw uploaded key bytes, before the key
	// was canonicalized; identical to the bare canonical form when the upload
	// was already canonical
	if !bytes.Equal(rawKey, canonicalKey) {
		rawSum := sha256.Sum256(rawKey)
		keys = append(keys, hex.EncodeToString(rawSum[:]))
	}
	return keys
}

// ArtifactHashIndexKey returns the canonical search-index key for an artifact
// digest, "<algorithm>:<value>". Every entry type must use this for keys
// derived from artifact digests.
func ArtifactHashIndexKey(algorithm, value string) string {
	return strings.ToLower(algorithm + ":" + value)
}

// ArtifactHashIndexKeys returns every form under which an artifact digest may
// have been indexed: the canonical algorithm-prefixed form first, then the
// historical bare-hex form written before digests were consistently prefixed.
// Entries already indexed under the bare form cannot be rewritten, so lookups
// must try both forms.
func ArtifactHashIndexKeys(hash string) []string {
	prefixed := strings.ToLower(PrefixSHA(hash))
	bare := prefixed
	if _, value, found := strings.Cut(prefixed, ":"); found {
		bare = value
	}
	if bare == "" || bare == prefixed {
		return []string{prefixed}
	}
	return []string{prefixed, bare}
}
