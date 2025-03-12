module css-git.juniper.net/google/gribiProgramWithGet

go 1.21.4

require (
	github.com/openconfig/gribi v1.0.0
	google.golang.org/protobuf v1.34.2
)

require (
	github.com/openconfig/ygot v0.29.19 // indirect
	google.golang.org/grpc v1.66.2
)

require (
	golang.org/x/net v0.30.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240903143218-8af14fe29dc1 // indirect
)

replace github.com/Juniper/telemetry/protos/junos-telemetry-interface/GnmiJuniperTelemetryHeaderExtension v0.0.0 => ./GNMIJuniperTelemetryExtension

replace github.com/Juniper/telemetry/protos/junos-telemetry-interface/GnmiJuniperTelemetryHeader v0.0.0 => ./GNMIJuniperTelemetryHeader
