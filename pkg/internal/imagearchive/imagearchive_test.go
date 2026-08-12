/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package imagearchive

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

// archiveBuilder assembles an OCI image layout archive in memory, keyed by the
// digest of each blob so tests can reference blobs they did or did not add
type archiveBuilder struct {
	t     *testing.T
	blobs map[string][]byte
}

func newArchive(t *testing.T) *archiveBuilder {
	return &archiveBuilder{t: t, blobs: map[string][]byte{}}
}

// blob adds contents to the archive and returns its digest
func (a *archiveBuilder) blob(contents interface{}) string {
	a.t.Helper()
	raw, err := json.Marshal(contents)
	if err != nil {
		a.t.Fatalf("failed to marshal blob: %v", err)
	}
	digest := digestOf(raw)
	a.blobs[digest] = raw
	return digest
}

// missingBlob returns the digest contents would have, without adding them
func (a *archiveBuilder) missingBlob(contents interface{}) string {
	a.t.Helper()
	raw, err := json.Marshal(contents)
	if err != nil {
		a.t.Fatalf("failed to marshal blob: %v", err)
	}
	return digestOf(raw)
}

// manifest adds a config and a layer plus the manifest referencing them
func (a *archiveBuilder) manifest(name string) string {
	a.t.Helper()
	config := a.blob(map[string]string{"config": name})
	layer := a.blob(map[string]string{"layer": name})
	return a.blob(map[string]interface{}{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config":    map[string]string{"digest": config},
		"layers":    []map[string]string{{"digest": layer}},
	})
}

func (a *archiveBuilder) tar(index interface{}) *bytes.Reader {
	a.t.Helper()
	files := map[string][]byte{}
	if index != nil {
		raw, err := json.Marshal(index)
		if err != nil {
			a.t.Fatalf("failed to marshal index: %v", err)
		}
		files["index.json"] = raw
	}
	for digest, contents := range a.blobs {
		files["blobs/sha256/"+digest[len("sha256:"):]] = contents
	}

	buf := &bytes.Buffer{}
	tw := tar.NewWriter(buf)
	for name, contents := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Size:     int64(len(contents)),
			Mode:     0644,
		}); err != nil {
			a.t.Fatalf("failed to write tar header: %v", err)
		}
		if _, err := tw.Write(contents); err != nil {
			a.t.Fatalf("failed to write tar contents: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		a.t.Fatalf("failed to close tar: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}

func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func descriptorFor(digest, os, arch string) map[string]interface{} {
	d := map[string]interface{}{"digest": digest}
	if os != "" {
		d["platform"] = map[string]string{"os": os, "architecture": arch}
	}
	return d
}

// indexJSON wraps children in the index blob that index.json points at, the
// shape `docker save` writes for a multi platform image
func (a *archiveBuilder) indexJSON(children ...map[string]interface{}) interface{} {
	index := a.blob(map[string]interface{}{
		"mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": children,
	})
	return map[string]interface{}{
		"manifests": []map[string]interface{}{{"digest": index}},
	}
}

func TestInspect(t *testing.T) {
	t.Parallel()

	t.Run("all platforms present", func(t *testing.T) {
		t.Parallel()
		a := newArchive(t)
		amd64 := a.manifest("amd64")
		arm64 := a.manifest("arm64")
		content := inspect(t, a.tar(a.indexJSON(
			descriptorFor(amd64, "linux", "amd64"),
			descriptorFor(arm64, "linux", "arm64"),
		)))
		assertContent(t, content, &Content{
			AllPresent: true,
			Complete:   []string{"linux/amd64", "linux/arm64"},
		})
	})

	t.Run("missing platform manifest", func(t *testing.T) {
		t.Parallel()
		a := newArchive(t)
		amd64 := a.manifest("amd64")
		arm64 := a.missingBlob(map[string]string{"manifest": "arm64"})
		content := inspect(t, a.tar(a.indexJSON(
			descriptorFor(amd64, "linux", "amd64"),
			descriptorFor(arm64, "linux", "arm64"),
		)))
		assertContent(t, content, &Content{
			Complete: []string{"linux/amd64"},
			Missing:  []string{"linux/arm64"},
		})
	})

	t.Run("missing layer", func(t *testing.T) {
		t.Parallel()
		a := newArchive(t)
		config := a.blob(map[string]string{"config": "amd64"})
		layer := a.missingBlob(map[string]string{"layer": "amd64"})
		amd64 := a.blob(map[string]interface{}{
			"config": map[string]string{"digest": config},
			"layers": []map[string]string{{"digest": layer}},
		})
		content := inspect(t, a.tar(a.indexJSON(descriptorFor(amd64, "linux", "amd64"))))
		assertContent(t, content, &Content{Missing: []string{"linux/amd64"}})
	})

	t.Run("missing attestation is not a platform", func(t *testing.T) {
		t.Parallel()
		a := newArchive(t)
		amd64 := a.manifest("amd64")
		attestation := a.missingBlob(map[string]string{"manifest": "attestation"})
		content := inspect(t, a.tar(a.indexJSON(
			descriptorFor(amd64, "linux", "amd64"),
			descriptorFor(attestation, "unknown", "unknown"),
		)))
		assertContent(t, content, &Content{Complete: []string{"linux/amd64"}})
	})

	t.Run("platform from config", func(t *testing.T) {
		t.Parallel()
		a := newArchive(t)
		config := a.blob(map[string]string{"os": "linux", "architecture": "arm", "variant": "v7"})
		layer := a.blob(map[string]string{"layer": "armv7"})
		armv7 := a.blob(map[string]interface{}{
			"config": map[string]string{"digest": config},
			"layers": []map[string]string{{"digest": layer}},
		})
		// index.json pointing straight at a manifest, as in a single platform
		// `docker save --platform`
		content := inspect(t, a.tar(map[string]interface{}{
			"manifests": []map[string]interface{}{{"digest": armv7}},
		}))
		assertContent(t, content, &Content{AllPresent: true, Complete: []string{"linux/arm/v7"}})
	})

	t.Run("shared platform is only complete when every image has it", func(t *testing.T) {
		t.Parallel()
		a := newArchive(t)
		first := a.manifest("first")
		config := a.blob(map[string]string{"config": "second"})
		second := a.blob(map[string]interface{}{
			"config": map[string]string{"digest": config},
			"layers": []map[string]string{{"digest": a.missingBlob(map[string]string{"layer": "second"})}},
		})
		index := a.blob(map[string]interface{}{
			"manifests": []map[string]interface{}{descriptorFor(second, "linux", "amd64")},
		})
		firstIndex := a.blob(map[string]interface{}{
			"manifests": []map[string]interface{}{descriptorFor(first, "linux", "amd64")},
		})
		content := inspect(t, a.tar(map[string]interface{}{
			"manifests": []map[string]interface{}{{"digest": firstIndex}, {"digest": index}},
		}))
		assertContent(t, content, &Content{Missing: []string{"linux/amd64"}})
	})

	t.Run("archive without an index is not inspected", func(t *testing.T) {
		t.Parallel()
		a := newArchive(t)
		a.manifest("amd64")
		content := inspect(t, a.tar(nil))
		if content != nil {
			t.Fatalf("expected nil content for a non OCI layout archive, got %+v", content)
		}
	})
}

func inspect(t *testing.T, archive *bytes.Reader) *Content {
	t.Helper()
	content, err := Inspect(archive)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return content
}

func assertContent(t *testing.T, actual, expected *Content) {
	t.Helper()
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("content did not match\nexpected: %s\nactual:   %s", format(expected), format(actual))
	}
}

func format(c *Content) string {
	if c == nil {
		return "nil"
	}
	return fmt.Sprintf("AllPresent=%v Complete=%v Missing=%v", c.AllPresent, c.Complete, c.Missing)
}
