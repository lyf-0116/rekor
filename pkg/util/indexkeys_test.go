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
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestPublicKeyIndexKey(t *testing.T) {
	canonical := []byte("canonical-key-bytes")
	sum := sha256.Sum256(canonical)
	want := "publickey:sha256:" + hex.EncodeToString(sum[:])
	if got := PublicKeyIndexKey(canonical); got != want {
		t.Errorf("PublicKeyIndexKey() = %q, want %q", got, want)
	}
}

func TestPublicKeyIndexKeys(t *testing.T) {
	canonical := []byte("canonical-key-bytes")
	raw := []byte("raw-key-bytes")
	canonicalSum := sha256.Sum256(canonical)
	bare := hex.EncodeToString(canonicalSum[:])
	rawSum := sha256.Sum256(raw)
	rawBare := hex.EncodeToString(rawSum[:])
	got := PublicKeyIndexKeys(canonical, raw)
	want := []string{
		"publickey:sha256:" + bare,
		bare,
		"sha256:" + bare,
		rawBare,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PublicKeyIndexKeys() = %v, want %v", got, want)
	}
	got = PublicKeyIndexKeys(canonical, canonical)
	if !reflect.DeepEqual(got, want[:3]) {
		t.Errorf("PublicKeyIndexKeys(same, same) = %v, want %v", got, want[:3])
	}
}

func TestArtifactHashIndexKey(t *testing.T) {
	if got := ArtifactHashIndexKey("SHA256", "ABC123"); got != "sha256:abc123" {
		t.Errorf("ArtifactHashIndexKey() = %q, want %q", got, "sha256:abc123")
	}
}

func TestArtifactHashIndexKeys(t *testing.T) {
	const bareSHA256 = "b9869be95b24001702120dd5dd673a9bd8447446fb57220388d8d0a48c738808"
	var testCases = []struct {
		input string
		want  []string
	}{
		{input: bareSHA256, want: []string{"sha256:" + bareSHA256, bareSHA256}},
		{input: "sha256:" + bareSHA256, want: []string{"sha256:" + bareSHA256, bareSHA256}},
		{input: "SHA256:" + bareSHA256, want: []string{"sha256:" + bareSHA256, bareSHA256}},
		{input: "sha512:abc", want: []string{"sha512:abc", "abc"}},
		{input: "not-a-hash", want: []string{"not-a-hash"}},
	}
	for _, tc := range testCases {
		if got := ArtifactHashIndexKeys(tc.input); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ArtifactHashIndexKeys(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}
