// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && !android
// +build linux,!android

package netlink

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeAndReleaseEvent(t *testing.T) {
	e := Event{
		msgs: []netlink.Message{
			{
				// orig_src=10.0.2.15:58472 orig_dst=2.2.2.2:5432 reply_src=1.1.1.1:5432 reply_dst=10.0.2.15:58472 proto=tcp(6)
				Data: []byte{0x2, 0x0, 0x0, 0x0, 0x34, 0x0, 0x1, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xa, 0x0, 0x2, 0xf, 0x8, 0x0, 0x2, 0x0, 0x2, 0x2, 0x2, 0x2, 0x1c, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x2, 0x0, 0xe4, 0x68, 0x0, 0x0, 0x6, 0x0, 0x3, 0x0, 0x15, 0x38, 0x0, 0x0, 0x34, 0x0, 0x2, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0x1, 0x1, 0x1, 0x1, 0x8, 0x0, 0x2, 0x0, 0xa, 0x0, 0x2, 0xf, 0x1c, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x2, 0x0, 0x15, 0x38, 0x0, 0x0, 0x6, 0x0, 0x3, 0x0, 0xe4, 0x68, 0x0, 0x0, 0x8, 0x0, 0xc, 0x0, 0x3e, 0x63, 0x25, 0x71, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x1, 0xa8, 0x8, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0, 0x78, 0x30, 0x0, 0x4, 0x80, 0x2c, 0x0, 0x1, 0x80, 0x5, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x0, 0x2, 0x0, 0x7, 0x0, 0x0, 0x0, 0x5, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x0, 0x4, 0x0, 0x3, 0x0, 0x0, 0x0, 0x6, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0},
			},
		},
	}

	decoder := NewDecoder()
	connections := decoder.DecodeAndReleaseEvent(e)
	assert.Len(t, connections, 1)
	c := connections[0]

	assert.True(t, net.ParseIP("10.0.2.15").Equal(*c.Origin.Src))
	assert.True(t, net.ParseIP("2.2.2.2").Equal(*c.Origin.Dst))

	assert.Equal(t, uint16(58472), *c.Origin.Proto.SrcPort)
	assert.Equal(t, uint16(5432), *c.Origin.Proto.DstPort)
	assert.Equal(t, uint8(6), *c.Origin.Proto.Number)

	assert.True(t, net.ParseIP("1.1.1.1").Equal(*c.Reply.Src))
	assert.True(t, net.ParseIP("10.0.2.15").Equal(*c.Reply.Dst))

	assert.Equal(t, uint16(5432), *c.Reply.Proto.SrcPort)
	assert.Equal(t, uint16(58472), *c.Reply.Proto.DstPort)
	assert.Equal(t, uint8(6), *c.Reply.Proto.Number)
}

func BenchmarkDecodeSingleMessage(b *testing.B) {
	b.ReportAllocs()
	messages, err := loadDumpData(b)
	if err != nil {
		b.Fatalf("unable to load dump data: %s", err)
	}
	require.GreaterOrEqual(b, len(messages), 1)

	e := Event{msgs: messages[:1]}
	decoder := NewDecoder()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		decoder.DecodeAndReleaseEvent(e)
	}
}

func BenchmarkDecodeMultipleMessages(b *testing.B) {
	b.ReportAllocs()
	messages, err := loadDumpData(b)
	if err != nil {
		b.Fatalf("unable to load dump data: %s", err)
	}
	require.GreaterOrEqual(b, len(messages), 1)

	e := Event{msgs: messages}
	decoder := NewDecoder()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		decoder.DecodeAndReleaseEvent(e)
	}
}

func loadDumpData(b require.TestingT) ([]netlink.Message, error) {
	f, err := ioutil.TempFile("", "message_dump")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	defer f.Close()

	testMessageDump(b, f, net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"))

	var messages []netlink.Message
	sizeBuffer := make([]byte, 4)
	for {
		_, err := io.ReadFull(f, sizeBuffer)
		if err != nil {
			break
		}

		size := binary.LittleEndian.Uint32(sizeBuffer)
		m := netlink.Message{Data: make([]byte, size)}
		_, err = io.ReadFull(f, m.Data)
		if err != nil {
			return nil, fmt.Errorf("couldn't read enough data")
		}

		messages = append(messages, m)
	}

	return messages, nil
}
