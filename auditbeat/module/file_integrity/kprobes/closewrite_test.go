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

package kprobes

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/elastic/beats/v7/auditbeat/tracing"
)

func Test_fsNotifySymbol_closeWriteFilters(t *testing.T) {
	disabled := &fsNotifySymbol{symbolName: "fsnotify"}
	disabled.setKprobeFilters(1, 2, 3)
	// with close write disabled the filters must be exactly the historical ones.
	require.Equal(t, "(mc==1 || md==1 || ma==1 || mm==1 || mmt==1 || mmf==1) && dt==1", disabled.pathProbeFilter)
	require.Equal(t, "(mc==1 || md==1 || ma==1 || mm==1 || mmt==1 || mmf==1) && dt==2 && nptr!=0", disabled.inodeProbeFilter)
	require.Equal(t, "(mc==1 || md==1 || ma==1 || mm==1 || mmt==1 || mmf==1) && dt==3", disabled.dentryProbeFilter)

	require.True(t, disabled.onErr(ErrVerifyOverlappingEvents))
	require.Equal(t, "(mc==1 || md==1 || ma==1 || mmt==1 || mmf==1) && dt==1", disabled.pathProbeFilter)
	require.True(t, disabled.onErr(ErrVerifyMissingEvents))
	require.Equal(t, "(mc==1 || md==1 || ma==1 || mm==1 || mmt==1 || mmf==1) && dt==2 && (nptr!=0 || (mid==1 && ma==1))", disabled.inodeProbeFilter)

	enabled := &fsNotifySymbol{symbolName: "fsnotify", closeWrite: true}
	enabled.setKprobeFilters(1, 2, 3)
	for _, f := range []string{enabled.pathProbeFilter, enabled.inodeProbeFilter, enabled.dentryProbeFilter} {
		require.Contains(t, f, "mm==1 || mcw==1")
	}

	// close write events follow modify events: when the parent probe takes
	// over modify events, it takes over close write events too.
	require.True(t, enabled.onErr(ErrVerifyOverlappingEvents))
	for _, f := range []string{enabled.pathProbeFilter, enabled.inodeProbeFilter, enabled.dentryProbeFilter} {
		require.NotContains(t, f, "mm==1")
		require.NotContains(t, f, "mcw==1")
	}
	require.True(t, enabled.onErr(ErrVerifyMissingEvents))
	for _, f := range []string{enabled.pathProbeFilter, enabled.inodeProbeFilter, enabled.dentryProbeFilter} {
		require.Contains(t, f, "mm==1 || mcw==1")
	}
}

func Test_fsNotifySymbols_closeWriteProbes(t *testing.T) {
	// FS_CLOSE_WRITE == IN_CLOSE_WRITE == 0x8
	require.Equal(t, uint32(0x8), fsEventCloseWrite)

	specs, err := loadEmbeddedSpecs()
	require.NoError(t, err)
	require.NotEmpty(t, specs)

	symbolInfo := func(symbolName string) (runtimeSymbolInfo, error) {
		if symbolName == "fsnotify" || symbolName == "__fsnotify_parent" {
			return runtimeSymbolInfo{symbolName: symbolName}, nil
		}
		return runtimeSymbolInfo{}, ErrSymbolNotFound
	}

	for _, closeWrite := range []bool{false, true} {
		prbMgr := &probeManager{getSymbolInfoRuntime: symbolInfo, closeWrite: closeWrite}
		require.NoError(t, loadFsNotifySymbol(prbMgr))
		require.NoError(t, loadFsNotifyParentSymbol(prbMgr))
		require.Len(t, prbMgr.symbols, 2)

		for _, spec := range specs {
			for _, sym := range prbMgr.symbols {
				if !spec.ContainsSymbol(sym.(interface{ name() string }).name()) {
					continue
				}
				probes, err := sym.buildProbes(spec)
				require.NoError(t, err)
				require.NotEmpty(t, probes)
				for _, p := range probes {
					fetchArgs := p.probe.GetTracingEventProbe()
					filter := p.probe.GetTracingEventFilter()
					require.Equal(t, closeWrite, strings.Contains(fetchArgs, "mcw="), "fetch args: %s", fetchArgs)
					require.Equal(t, closeWrite, strings.Contains(filter, "mcw==1"), "filter: %s", filter)
				}
			}
		}
	}
}

func (sym *fsNotifySymbol) name() string     { return sym.symbolName }
func (f *fsNotifyParentSymbol) name() string { return f.symbolName }

func Test_EventProcessor_closeWrite(t *testing.T) {
	emitter := &EmitterMock{}
	emitter.On("Emit", "/root/file", uint32(42), uint32(unix.IN_CLOSE_WRITE)).Return(nil).Once()

	e := newEventProcessor(&pathTraverserMock{}, emitter, true)
	root := &dEntry{Name: "/root", Ino: 1, DevMajor: 1, DevMinor: 1}
	e.cache.Add(root, nil)
	e.cache.Add(&dEntry{Name: "file", Ino: 2, DevMajor: 1, DevMinor: 1}, root)

	// unknown inode: ignored, like modify events.
	require.NoError(t, e.process(&ProbeEvent{
		Meta:           tracing.Metadata{TID: 42},
		MaskCloseWrite: 1,
		FileIno:        3, FileDevMajor: 1, FileDevMinor: 1,
	}))
	require.NoError(t, e.process(&ProbeEvent{
		Meta:           tracing.Metadata{TID: 42},
		MaskCloseWrite: 1,
		FileIno:        2, FileDevMajor: 1, FileDevMinor: 1,
	}))
	emitter.AssertExpectations(t)
	emitter.AssertNumberOfCalls(t, "Emit", 1)
}

func Test_EventsVerifier_closeWrite(t *testing.T) {
	for _, closeWrite := range []bool{false, true} {
		tmpDir := t.TempDir()
		e, err := newEventsVerifier(tmpDir)
		require.NoError(t, err)
		e.closeWrite = closeWrite

		require.NoError(t, e.GenerateEvents())

		closeWrites := 0
		for id, n := range e.eventsToExpect {
			if id.op == unix.IN_CLOSE_WRITE {
				closeWrites += n
			}
		}
		if closeWrite {
			// the create and write generators open the file for writing.
			require.Equal(t, 2, closeWrites)
		} else {
			require.Zero(t, closeWrites)
		}
	}
}
