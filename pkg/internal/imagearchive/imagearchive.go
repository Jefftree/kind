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

// Package imagearchive inspects image archives in the OCI image layout format,
// as written by `docker save`, `podman save` and `nerdctl save`.
package imagearchive

import (
	"archive/tar"
	"encoding/json"
	"io"
	"path"
	"sort"
	"strings"

	"sigs.k8s.io/kind/pkg/errors"
)

// maxMetadataSize bounds the blobs we buffer while scanning. Indexes, manifests
// and configs are small, layers are not and we only need their presence.
const maxMetadataSize = 1 << 20

// Content summarizes the platform content of an image archive
type Content struct {
	// AllPresent is true when every blob referenced by the archive is in it,
	// meaning the archive can be imported with --all-platforms
	AllPresent bool
	// Complete lists the platforms ("os/arch[/variant]") whose manifest, config
	// and layers are all present in the archive
	Complete []string
	// Missing lists the platforms referenced by the archive that are not
	// completely present in it
	Missing []string
}

type descriptor struct {
	MediaType string    `json:"mediaType"`
	Digest    string    `json:"digest"`
	Platform  *platform `json:"platform,omitempty"`
}

type platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

func (p *platform) String() string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// known returns false for the "unknown/unknown" platform used by attestation
// manifests, which are not selectable by platform
func (p *platform) known() bool {
	return p != nil && p.OS != "" && p.OS != "unknown" && p.Architecture != "" && p.Architecture != "unknown"
}

// blob is either an index or a manifest, we only unmarshal what tells them apart
type blob struct {
	Manifests []descriptor `json:"manifests"`
	Config    *descriptor  `json:"config"`
	Layers    []descriptor `json:"layers"`
}

// imageConfig is the subset of an image config we need to identify the platform
// of a manifest that is not described by a platform in its descriptor
type imageConfig struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

// Inspect reads an image archive and reports which platforms it fully contains.
//
// It returns nil for archives that are not in the OCI image layout format, such
// as those written by older docker versions, which have nothing to inspect.
func Inspect(archive io.Reader) (*Content, error) {
	// blobs maps digest to contents, with a nil value for blobs too large to
	// buffer, so presence is a key lookup and never a nil check
	blobs := map[string][]byte{}
	var index []byte

	tr := tar.NewReader(archive)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "failed to read image archive")
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(hdr.Name)
		if name == "index.json" {
			index, err = io.ReadAll(tr)
			if err != nil {
				return nil, errors.Wrap(err, "failed to read index.json from image archive")
			}
			continue
		}
		// blobs are stored at blobs/<algorithm>/<encoded>
		parts := strings.Split(name, "/")
		if len(parts) != 3 || parts[0] != "blobs" {
			continue
		}
		digest := parts[1] + ":" + parts[2]
		if hdr.Size > maxMetadataSize {
			blobs[digest] = nil
			continue
		}
		contents, err := io.ReadAll(tr)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read %s from image archive", name)
		}
		blobs[digest] = contents
	}

	// not an OCI image layout archive, there is nothing to inspect
	if index == nil {
		return nil, nil
	}

	parsed := struct {
		Manifests []descriptor `json:"manifests"`
	}{}
	if err := json.Unmarshal(index, &parsed); err != nil {
		return nil, errors.Wrap(err, "failed to parse index.json from image archive")
	}

	s := &scanner{
		blobs:      blobs,
		seen:       map[string]bool{},
		platforms:  map[string]bool{},
		allPresent: true,
	}
	for _, d := range parsed.Manifests {
		s.walk(d)
	}
	return s.result(), nil
}

type scanner struct {
	blobs map[string][]byte
	seen  map[string]bool
	// platforms maps platform to whether all of its content is present, shared
	// across the images in the archive, which commonly share platforms
	platforms  map[string]bool
	allPresent bool
}

func (s *scanner) result() *Content {
	content := &Content{AllPresent: s.allPresent}
	for name, complete := range s.platforms {
		if complete {
			content.Complete = append(content.Complete, name)
		} else {
			content.Missing = append(content.Missing, name)
		}
	}
	sort.Strings(content.Complete)
	sort.Strings(content.Missing)
	return content
}

// walk descends into d, recording the platforms it finds and whether anything
// it references is missing from the archive
func (s *scanner) walk(d descriptor) {
	contents, present := s.blobs[d.Digest]
	if !present {
		s.allPresent = false
		s.record(d.Platform, false)
		return
	}
	if s.seen[d.Digest] {
		return
	}
	s.seen[d.Digest] = true

	// contents is nil for blobs too large to have buffered, which are layers
	// and never something we descend into
	var b blob
	if contents == nil || json.Unmarshal(contents, &b) != nil {
		return
	}

	if len(b.Manifests) > 0 {
		for _, child := range b.Manifests {
			s.walk(child)
		}
		return
	}

	// not a manifest either, nothing else references content
	if b.Config == nil {
		return
	}

	config, complete := s.blobs[b.Config.Digest]
	for _, l := range b.Layers {
		if _, ok := s.blobs[l.Digest]; !ok {
			complete = false
		}
	}
	if !complete {
		s.allPresent = false
	}

	p := d.Platform
	if p == nil {
		p = platformFromConfig(config)
	}
	s.record(p, complete)
}

func (s *scanner) record(p *platform, complete bool) {
	// attestations and other non-platform content can only be skipped, never
	// selected, so they are not a platform we can ask containerd to import
	if !p.known() {
		return
	}
	name := p.String()
	if was, seen := s.platforms[name]; seen && !was {
		return
	}
	s.platforms[name] = complete
}

// platformFromConfig recovers the platform of a manifest whose descriptor does
// not carry one, as in single platform archives where index.json points
// directly at the manifest
func platformFromConfig(config []byte) *platform {
	if config == nil {
		return nil
	}
	var c imageConfig
	if json.Unmarshal(config, &c) != nil {
		return nil
	}
	return &platform{OS: c.OS, Architecture: c.Architecture, Variant: c.Variant}
}
