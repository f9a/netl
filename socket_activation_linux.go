// +build linux

package netl

import (
	"errors"
	"fmt"
	"net"

	"github.com/coreos/go-systemd/activation"
)

func receiveSocketFromSystemd(socketName string) (listener net.Listener, err error) {
	var listeners []net.Listener
	if socketName == "" {
		listeners, err = activation.Listeners()
		if err != nil {
			err = fmt.Errorf("couldn't get listeners for socket activation: %v", err)
			return
		}
	} else {
		var listenerIdx map[string][]net.Listener
		listenerIdx, err = activation.ListenersWithNames()
		if err != nil {
			err = fmt.Errorf("couldn't get listeners for socket activation: %v", err)
			return
		}

		var ok bool
		listeners, ok = listenerIdx[socketName]
		if ok {
			err = errors.New("no listener found for given socket name")
			return
		}
	}

	if len(listeners) != 1 {
		err = errors.New("an unexpected number of socket activations was found")
		return
	}

	return listeners[0], nil
}
