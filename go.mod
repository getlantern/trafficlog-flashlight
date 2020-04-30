module github.com/getlantern/trafficlog-flashlight

go 1.13

require (
	github.com/getlantern/authipc v0.0.0-20200427172522-2a37bab4dd74
	github.com/getlantern/byteexec v0.0.0-20170405023437-4cfb26ec74f4
	github.com/getlantern/elevate v0.0.0-20180207094634-c2e2e4901072
	github.com/getlantern/golog v0.0.0-20190830074920-4ef2e798c2d7
	github.com/getlantern/trafficlog v0.0.0-20200417192526-a0b1f8bd93bd
	github.com/stretchr/testify v1.5.1
	golang.org/x/sys v0.0.0-20200427175716-29b57079015a
)

// TODO: upload repos and use remote versions

replace github.com/getlantern/trafficlog => ../trafficlog

replace github.com/getlantern/authipc => ../authipc
