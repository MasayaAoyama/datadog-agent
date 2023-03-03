// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs -- -I ../ebpf/c -I ../../ebpf/c -fsigned-char types.go

package protocols

type ProtocolType = uint16

const (
	Unknown  ProtocolType = 0x0
	HTTP     ProtocolType = 0x4001
	HTTP2    ProtocolType = 0x4002
	Kafka    ProtocolType = 0x4003
	TLS      ProtocolType = 0x8001
	Mongo    ProtocolType = 0x4004
	Postgres ProtocolType = 0x4005
	AMQP     ProtocolType = 0x4006
	Redis    ProtocolType = 0x4007
	MySQL    ProtocolType = 0x4008
)

type DispatcherProgramType uint32

const (
	DispatcherKafkaProg DispatcherProgramType = 0x0
)

type ProgramType uint32

const (
	ProgramHTTP  ProgramType = 0x1
	ProgramHTTP2 ProgramType = 0x2
	ProgramKafka ProgramType = 0x3
)

const (
	layerAPIBit         = 0x2000
	layerApplicationBit = 0x4000
	layerEncryptionBit  = 0x8000
)
