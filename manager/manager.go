package manager

import (
	"context"
	"os"
	"path"

	"github.com/nathan-osman/go-simpleacme"
)

// Manager manages certificates for a sequence of domain names
type Manager struct {
	stop    chan bool
	stopped chan bool
	dir     string
	client  *simpleacme.Client
}

// run monitors certificates for expiry and renews them if necessary.
func (m *Manager) run() {
	defer close(m.stopped)
	for {
		select {
		case <-m.stop:
			return
		}
	}
}

// Create a new certificate manager using the specified directory.
func New(ctx context.Context, dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	c, err := simpleacme.New(ctx, path.Join(dir, "account.key"))
	if err != nil {
		return nil, err
	}
	m := &Manager{
		stop:    make(chan bool),
		stopped: make(chan bool),
		dir:     dir,
		client:  c,
	}
	go m.run()
	return m, nil
}

// Close the certificate manager.
func (m *Manager) Close() {
	close(m.stop)
	<-m.stopped
}
