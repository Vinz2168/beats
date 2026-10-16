// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package file_integrity

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/auditbeat/ab"
	"github.com/elastic/beats/v7/auditbeat/datastore"
	mbtest "github.com/elastic/beats/v7/metricbeat/mb/testing"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp/logptest"
)

func TestClosedWriteAction(t *testing.T) {
	closedWrite := Action(ClosedWrite)
	assert.Equal(t, "closed_write", closedWrite.String())
	assert.Equal(t, []string{"change"}, closedWrite.ECSTypes())
	assert.Equal(t, ActionArray{closedWrite}, closedWrite.InOrder(true, true))
	assert.Equal(t, ActionArray{closedWrite}, closedWrite.InOrder(false, true))
	assert.Equal(t, []string{"closed_write"}, closedWrite.InOrder(true, true).StringArray())
	// Action is a uint8 bitmask: ClosedWrite must not overlap other actions.
	for a := range actionNames {
		if a != ClosedWrite {
			assert.Zero(t, a&ClosedWrite, a.String())
		}
	}
}

func TestConfigEmitCloseWrite(t *testing.T) {
	assert.False(t, defaultConfig.EmitCloseWrite, "emit_close_write must be opt-in")

	unpack := func(t *testing.T, fields map[string]any) (Config, error) {
		t.Helper()
		fields["paths"] = []string{t.TempDir()}
		config, err := conf.NewConfigFrom(fields)
		require.NoError(t, err)
		c := defaultConfig
		return c, config.Unpack(&c)
	}

	c, err := unpack(t, map[string]any{})
	require.NoError(t, err)
	assert.False(t, c.EmitCloseWrite)

	if runtime.GOOS != "linux" {
		_, err = unpack(t, map[string]any{"emit_close_write": true})
		assert.ErrorContains(t, err, "emit_close_write is only supported on linux")
		return
	}

	for _, backend := range []string{"", "auto", "fsnotify", "kprobes"} {
		fields := map[string]any{"emit_close_write": true}
		if backend != "" {
			fields["backend"] = backend
		}
		c, err = unpack(t, fields)
		require.NoError(t, err, backend)
		assert.True(t, c.EmitCloseWrite, backend)
	}

	_, err = unpack(t, map[string]any{"emit_close_write": true, "backend": "ebpf"})
	assert.ErrorContains(t, err, "emit_close_write is not supported by the ebpf backend")
}

func TestEventClosedWrite(t *testing.T) {
	bucket, err := datastore.OpenBucket(bucketName, testPaths(t.TempDir()), logptest.NewTestingLogger(t, ""))
	require.NoError(t, err)
	defer bucket.Close()
	config := getConfig("somepath")
	config["hash_types"] = []string{"sha256"}
	ms, ok := mbtest.NewPushMetricSetV2WithRegistry(t, config, ab.Registry).(*MetricSet)
	require.True(t, ok, "can't create metricset")
	ms.bucket = bucket.(datastore.BoltBucket) //nolint:errcheck // type is guaranteed by OpenBucket

	baseTime := time.Now()
	shaA := Digest("11111111111111111111")
	shaB := Digest("22222222222222222222")
	info := func(size uint64, mtime time.Time) *Metadata {
		return &Metadata{Size: size, MTime: mtime, CTime: mtime, Type: FileType}
	}
	event := func(action Action, sha Digest, md *Metadata) *Event {
		e := &Event{
			Timestamp: time.Now(),
			Path:      "/upload/file",
			Info:      md,
			Action:    action,
			Source:    SourceFSNotify,
		}
		if sha != nil {
			e.Hashes = map[HashType]Digest{SHA256: sha}
		}
		return e
	}
	assertStored := func(t *testing.T, sha Digest, size uint64) {
		t.Helper()
		stored, err := load(ms.bucket, "/upload/file")
		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.Equal(t, sha, stored.Hashes[SHA256])
		assert.Equal(t, size, stored.Info.Size)
	}

	checkExpectedEvent(t, ms, "created", event(Created, shaA, info(5, baseTime)), map[string]any{
		"event.action": []string{"created"},
	})
	checkExpectedEvent(t, ms, "updated without changes is deduplicated", event(Updated, shaA, info(5, baseTime)), nil)

	checkExpectedEvent(t, ms, "closed_write with same state is published", event(ClosedWrite, shaA, info(5, baseTime)), map[string]any{
		"event.action":     []string{"closed_write"},
		"event.type":       []string{"change"},
		"file.hash.sha256": shaA,
		"file.size":        uint64(5),
	})
	assertStored(t, shaA, 5)

	// Hash and size changed since the last event: event.action must still only
	// contain closed_write (not updated/attributes_modified).
	later := baseTime.Add(time.Second)
	checkExpectedEvent(t, ms, "closed_write with changes", event(ClosedWrite, shaB, info(10, later)), map[string]any{
		"event.action":     []string{"closed_write"},
		"event.type":       []string{"change"},
		"file.hash.sha256": shaB,
		"file.size":        uint64(10),
	})
	// The state was persisted: an update matching it is not reported.
	assertStored(t, shaB, 10)
	checkExpectedEvent(t, ms, "updated matching closed_write state", event(Updated, shaB, info(10, later)), nil)

	checkExpectedEvent(t, ms, "closed_write again", event(ClosedWrite, shaB, info(10, later)), map[string]any{
		"event.action": []string{"closed_write"},
	})

	// File removed before the close was processed (e.g. renamed by the client).
	checkExpectedEvent(t, ms, "closed_write for a missing file", event(ClosedWrite, nil, nil), map[string]any{
		"event.action": []string{"closed_write"},
		"file.size":    nil,
	})
	stored, err := load(ms.bucket, "/upload/file")
	require.NoError(t, err)
	assert.Nil(t, stored)
}
