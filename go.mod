module github.com/getlantern/trafficlog-flashlight

go 1.13

require (
	github.com/getlantern/authipc v0.0.0-20200417191816-cd39f96b445b
	github.com/getlantern/byteexec v0.0.0-20170405023437-4cfb26ec74f4
	github.com/getlantern/trafficlog v0.0.0-20200417192526-a0b1f8bd93bd
	github.com/stretchr/testify v1.5.1
)

// TODO: upload repos and use remote versions

replace github.com/getlantern/trafficlog => ../trafficlog

replace github.com/getlantern/authipc => ../authipc
