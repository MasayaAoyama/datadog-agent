// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package pb

// Code generated by github.com/tinylib/msgp DO NOT EDIT.

import (
	_ "github.com/gogo/protobuf/gogoproto"
	"github.com/tinylib/msgp/msgp"
)

// MarshalMsg implements msgp.Marshaler
func (z *TraceChunk) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 5
	// string "priority"
	o = append(o, 0x85, 0xa8, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79)
	o = msgp.AppendInt32(o, z.Priority)
	// string "origin"
	o = append(o, 0xa6, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e)
	o = msgp.AppendString(o, z.Origin)
	// string "spans"
	o = append(o, 0xa5, 0x73, 0x70, 0x61, 0x6e, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Spans)))
	for za0001 := range z.Spans {
		if z.Spans[za0001] == nil {
			o = msgp.AppendNil(o)
		} else {
			o, err = z.Spans[za0001].MarshalMsg(o)
			if err != nil {
				err = msgp.WrapError(err, "Spans", za0001)
				return
			}
		}
	}
	// string "tags"
	o = append(o, 0xa4, 0x74, 0x61, 0x67, 0x73)
	o = msgp.AppendMapHeader(o, uint32(len(z.Tags)))
	for za0002, za0003 := range z.Tags {
		o = msgp.AppendString(o, za0002)
		o = msgp.AppendString(o, za0003)
	}
	// string "dropped_trace"
	o = append(o, 0xad, 0x64, 0x72, 0x6f, 0x70, 0x70, 0x65, 0x64, 0x5f, 0x74, 0x72, 0x61, 0x63, 0x65)
	o = msgp.AppendBool(o, z.DroppedTrace)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *TraceChunk) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "priority":
			z.Priority, bts, err = msgp.ReadInt32Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Priority")
				return
			}
		case "origin":
			z.Origin, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Origin")
				return
			}
		case "spans":
			var zb0002 uint32
			zb0002, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Spans")
				return
			}
			if cap(z.Spans) >= int(zb0002) {
				z.Spans = (z.Spans)[:zb0002]
			} else {
				z.Spans = make([]*Span, zb0002)
			}
			for za0001 := range z.Spans {
				if msgp.IsNil(bts) {
					bts, err = msgp.ReadNilBytes(bts)
					if err != nil {
						return
					}
					z.Spans[za0001] = nil
				} else {
					if z.Spans[za0001] == nil {
						z.Spans[za0001] = new(Span)
					}
					bts, err = z.Spans[za0001].UnmarshalMsg(bts)
					if err != nil {
						err = msgp.WrapError(err, "Spans", za0001)
						return
					}
				}
			}
		case "tags":
			var zb0003 uint32
			zb0003, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Tags")
				return
			}
			if z.Tags == nil {
				z.Tags = make(map[string]string, zb0003)
			} else if len(z.Tags) > 0 {
				for key := range z.Tags {
					delete(z.Tags, key)
				}
			}
			for zb0003 > 0 {
				var za0002 string
				var za0003 string
				zb0003--
				za0002, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Tags")
					return
				}
				za0003, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Tags", za0002)
					return
				}
				z.Tags[za0002] = za0003
			}
		case "dropped_trace":
			z.DroppedTrace, bts, err = msgp.ReadBoolBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "DroppedTrace")
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *TraceChunk) Msgsize() (s int) {
	s = 1 + 9 + msgp.Int32Size + 7 + msgp.StringPrefixSize + len(z.Origin) + 6 + msgp.ArrayHeaderSize
	for za0001 := range z.Spans {
		if z.Spans[za0001] == nil {
			s += msgp.NilSize
		} else {
			s += z.Spans[za0001].Msgsize()
		}
	}
	s += 5 + msgp.MapHeaderSize
	if z.Tags != nil {
		for za0002, za0003 := range z.Tags {
			_ = za0003
			s += msgp.StringPrefixSize + len(za0002) + msgp.StringPrefixSize + len(za0003)
		}
	}
	s += 14 + msgp.BoolSize
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *TracerPayload) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 10
	// string "container_id"
	o = append(o, 0x8a, 0xac, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x5f, 0x69, 0x64)
	o = msgp.AppendString(o, z.ContainerID)
	// string "language_name"
	o = append(o, 0xad, 0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65)
	o = msgp.AppendString(o, z.LanguageName)
	// string "language_version"
	o = append(o, 0xb0, 0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e)
	o = msgp.AppendString(o, z.LanguageVersion)
	// string "tracer_version"
	o = append(o, 0xae, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e)
	o = msgp.AppendString(o, z.TracerVersion)
	// string "runtime_id"
	o = append(o, 0xaa, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x69, 0x64)
	o = msgp.AppendString(o, z.RuntimeID)
	// string "chunks"
	o = append(o, 0xa6, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Chunks)))
	for za0001 := range z.Chunks {
		if z.Chunks[za0001] == nil {
			o = msgp.AppendNil(o)
		} else {
			o, err = z.Chunks[za0001].MarshalMsg(o)
			if err != nil {
				err = msgp.WrapError(err, "Chunks", za0001)
				return
			}
		}
	}
	// string "tags"
	o = append(o, 0xa4, 0x74, 0x61, 0x67, 0x73)
	o = msgp.AppendMapHeader(o, uint32(len(z.Tags)))
	for za0002, za0003 := range z.Tags {
		o = msgp.AppendString(o, za0002)
		o = msgp.AppendString(o, za0003)
	}
	// string "env"
	o = append(o, 0xa3, 0x65, 0x6e, 0x76)
	o = msgp.AppendString(o, z.Env)
	// string "hostname"
	o = append(o, 0xa8, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65)
	o = msgp.AppendString(o, z.Hostname)
	// string "app_version"
	o = append(o, 0xab, 0x61, 0x70, 0x70, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e)
	o = msgp.AppendString(o, z.AppVersion)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *TracerPayload) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "container_id":
			z.ContainerID, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "ContainerID")
				return
			}
		case "language_name":
			z.LanguageName, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "LanguageName")
				return
			}
		case "language_version":
			z.LanguageVersion, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "LanguageVersion")
				return
			}
		case "tracer_version":
			z.TracerVersion, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "TracerVersion")
				return
			}
		case "runtime_id":
			z.RuntimeID, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "RuntimeID")
				return
			}
		case "chunks":
			var zb0002 uint32
			zb0002, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Chunks")
				return
			}
			if cap(z.Chunks) >= int(zb0002) {
				z.Chunks = (z.Chunks)[:zb0002]
			} else {
				z.Chunks = make([]*TraceChunk, zb0002)
			}
			for za0001 := range z.Chunks {
				if msgp.IsNil(bts) {
					bts, err = msgp.ReadNilBytes(bts)
					if err != nil {
						return
					}
					z.Chunks[za0001] = nil
				} else {
					if z.Chunks[za0001] == nil {
						z.Chunks[za0001] = new(TraceChunk)
					}
					bts, err = z.Chunks[za0001].UnmarshalMsg(bts)
					if err != nil {
						err = msgp.WrapError(err, "Chunks", za0001)
						return
					}
				}
			}
		case "tags":
			var zb0003 uint32
			zb0003, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Tags")
				return
			}
			if z.Tags == nil {
				z.Tags = make(map[string]string, zb0003)
			} else if len(z.Tags) > 0 {
				for key := range z.Tags {
					delete(z.Tags, key)
				}
			}
			for zb0003 > 0 {
				var za0002 string
				var za0003 string
				zb0003--
				za0002, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Tags")
					return
				}
				za0003, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Tags", za0002)
					return
				}
				z.Tags[za0002] = za0003
			}
		case "env":
			z.Env, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Env")
				return
			}
		case "hostname":
			z.Hostname, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Hostname")
				return
			}
		case "app_version":
			z.AppVersion, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "AppVersion")
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *TracerPayload) Msgsize() (s int) {
	s = 1 + 13 + msgp.StringPrefixSize + len(z.ContainerID) + 14 + msgp.StringPrefixSize + len(z.LanguageName) + 17 + msgp.StringPrefixSize + len(z.LanguageVersion) + 15 + msgp.StringPrefixSize + len(z.TracerVersion) + 11 + msgp.StringPrefixSize + len(z.RuntimeID) + 7 + msgp.ArrayHeaderSize
	for za0001 := range z.Chunks {
		if z.Chunks[za0001] == nil {
			s += msgp.NilSize
		} else {
			s += z.Chunks[za0001].Msgsize()
		}
	}
	s += 5 + msgp.MapHeaderSize
	if z.Tags != nil {
		for za0002, za0003 := range z.Tags {
			_ = za0003
			s += msgp.StringPrefixSize + len(za0002) + msgp.StringPrefixSize + len(za0003)
		}
	}
	s += 4 + msgp.StringPrefixSize + len(z.Env) + 9 + msgp.StringPrefixSize + len(z.Hostname) + 12 + msgp.StringPrefixSize + len(z.AppVersion)
	return
}
