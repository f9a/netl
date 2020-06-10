package netl

import "net"

func receiveSocketFromSystemd(socketName string) (net.Listener, error) {
	panic("socket-activation is not supported for the selected operating system.")
}
