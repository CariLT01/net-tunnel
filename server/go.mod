module github.com/CariLT01/lt-vpn2-server

go 1.25.8

require (
	github.com/cloudflare/circl v1.6.3
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/gorilla/websocket v1.5.3
	golang.org/x/time v0.15.0
)

require golang.org/x/sys v0.42.0 // indirect

require github.com/CariLT01/net-tunnel-common v0.0.0

replace github.com/CariLT01/net-tunnel-common => ../common
