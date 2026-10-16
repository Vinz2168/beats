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

//go:build linux

package file_integrity

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/elastic/elastic-agent-libs/logp/logptest"
)

func TestOpToActionCloseWrite(t *testing.T) {
	assert.EqualValues(t, ClosedWrite, opToAction(fsnotify.CloseWrite))
	assert.EqualValues(t, Updated, opToAction(fsnotify.Write))
	// Combined ops are not mapped (inotify reports one op per event).
	assert.EqualValues(t, None, opToAction(fsnotify.Write|fsnotify.CloseWrite))
}

func TestKProbeTypeToActionCloseWrite(t *testing.T) {
	assert.EqualValues(t, ClosedWrite, kProbeTypeToAction(unix.IN_CLOSE_WRITE))
	assert.EqualValues(t, Updated, kProbeTypeToAction(unix.IN_MODIFY))
	assert.EqualValues(t, None, kProbeTypeToAction(unix.IN_CLOSE_NOWRITE))
}

// startCloseWriteReader starts a fsnotify event reader for dir.
func startCloseWriteReader(t *testing.T, dir string, emitCloseWrite bool) <-chan Event {
	t.Helper()
	config := defaultConfig
	config.Paths = []string{dir}
	config.Recursive = true
	config.Backend = BackendFSNotify
	config.EmitCloseWrite = emitCloseWrite
	require.NoError(t, config.Validate())

	r, err := NewEventReader(config, logptest.NewTestingLogger(t, ""))
	require.NoError(t, err)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	events, err := r.Start(done)
	require.NoError(t, err)
	return events
}

// drain returns all the events received until no event arrives for 300ms.
func drain(t *testing.T, events <-chan Event) []Event {
	t.Helper()
	var received []Event
	for {
		select {
		case e, ok := <-events:
			require.True(t, ok, "event channel closed")
			received = append(received, e)
		case <-time.After(300 * time.Millisecond):
			return received
		}
	}
}

func closedWrites(events []Event, path string) []Event {
	var result []Event
	for _, e := range events {
		if e.Action == ClosedWrite && e.Path == path {
			result = append(result, e)
		}
	}
	return result
}

func countClosedWrites(events []Event) int {
	n := 0
	for _, e := range events {
		if e.Action&ClosedWrite != 0 {
			n++
		}
	}
	return n
}

func TestFSNotifyCloseWrite(t *testing.T) {
	dir := t.TempDir()
	events := startCloseWriteReader(t, dir, true)
	file := filepath.Join(dir, "upload.bin")

	t.Run("multi-chunk write", func(t *testing.T) {
		f, err := os.Create(file)
		require.NoError(t, err)
		for i := 0; i < 3; i++ {
			_, err = f.WriteString("chunk\n")
			require.NoError(t, err)
			time.Sleep(50 * time.Millisecond)
		}
		received := drain(t, events)
		assert.NotEmpty(t, received, "expected created/updated events")
		assert.Zero(t, countClosedWrites(received), "closed_write before Close()")

		require.NoError(t, f.Close())
		received = drain(t, events)
		cw := closedWrites(received, file)
		require.Len(t, cw, 1, "expected exactly one closed_write: %v", received)
		require.NotNil(t, cw[0].Info)
		assert.EqualValues(t, 18, cw[0].Info.Size)
		assert.NotEmpty(t, cw[0].Hashes)
		assert.Equal(t, countClosedWrites(received), 1)
	})

	t.Run("open for write without writing", func(t *testing.T) {
		// The kernel reports IN_CLOSE_WRITE for every close of a file opened
		// with write access, even if nothing was written.
		f, err := os.OpenFile(file, os.O_WRONLY, 0)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		received := drain(t, events)
		require.Len(t, closedWrites(received, file), 1, "%v", received)
		assert.Equal(t, 1, countClosedWrites(received))
	})

	t.Run("read-only open", func(t *testing.T) {
		f, err := os.Open(file)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		assert.Zero(t, countClosedWrites(drain(t, events)))
	})

	t.Run("rename", func(t *testing.T) {
		renamed := filepath.Join(dir, "renamed.bin")
		require.NoError(t, os.Rename(file, renamed))
		received := drain(t, events)
		var moved, created bool
		for _, e := range received {
			moved = moved || (e.Path == file && e.Action == Moved)
			created = created || (e.Path == renamed && e.Action == Created)
		}
		assert.True(t, moved, "expected moved event: %v", received)
		assert.True(t, created, "expected created event: %v", received)
		assert.Zero(t, countClosedWrites(received), "spurious closed_write: %v", received)
	})

	t.Run("recursive", func(t *testing.T) {
		sub := filepath.Join(dir, "a", "b")
		require.NoError(t, os.MkdirAll(sub, 0o755))
		drain(t, events) // wait for the watches on the new directories
		nested := filepath.Join(sub, "nested.bin")
		require.NoError(t, os.WriteFile(nested, []byte("nested"), 0o600))
		received := drain(t, events)
		require.Len(t, closedWrites(received, nested), 1, "%v", received)
		assert.Equal(t, 1, countClosedWrites(received))
	})
}

func TestFSNotifyCloseWriteDisabled(t *testing.T) {
	dir := t.TempDir()
	events := startCloseWriteReader(t, dir, false)

	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, []byte("data"), 0o600))
	f, err := os.OpenFile(file, os.O_WRONLY, 0)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	received := drain(t, events)
	assert.NotEmpty(t, received)
	assert.Zero(t, countClosedWrites(received), "%v", received)
}
