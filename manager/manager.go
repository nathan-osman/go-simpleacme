package manager

import (
	"context"
	"os"
	"path"
	"time"

	"github.com/nathan-osman/go-simpleacme"
	"github.com/sirupsen/logrus"
)

// Manager manages certificates for a sequence of domain names
type Manager struct {
	add     chan []string
	remove  chan []string
	stop    chan bool
	stopped chan bool
	addr    string
	dir     string
	log     *logrus.Entry
	client  *simpleacme.Client
	certs   map[string]time.Time
}

// nextExpiry calculates when the next certificate will expire. If none are
// expiring, nil is returned.
func (m *Manager) nextExpiry() <-chan time.Time {
	if len(m.certs) == 0 {
		return nil
	}
	var nextExpiry time.Time
	for _, expires := range m.certs {
		if nextExpiry.IsZero() || expires.Before(nextExpiry) {
			nextExpiry = expires
		}
	}
	return time.After(nextExpiry.Sub(time.Now()))
}

// run monitors certificates for expiry and renews them if necessary.
func (m *Manager) run() {
	defer close(m.stopped)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-m.stop
		cancel()
	}()
	for {
		select {
		case domains := <-m.add:
			for _, d := range domains {
				m.certs[d] = time.Time{}
			}
		case domains := <-m.remove:
			for _, d := range domains {
				delete(m.certs, d)
			}
		case <-m.nextExpiry():
		case <-ctx.Done():
			return
		}
		if err := m.renew(ctx); err != nil {
			if err == context.Canceled {
				return
			}
			m.log.Error(err)
			select {
			case <-time.After(30 * time.Second):
			case <-ctx.Done():
				return
			}
		}
	}
}

// Create a new certificate manager using the specified address and directory.
func New(ctx context.Context, addr, dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	c, err := simpleacme.New(ctx, path.Join(dir, "account.key"))
	if err != nil {
		return nil, err
	}
	m := &Manager{
		add:     make(chan []string),
		remove:  make(chan []string),
		stop:    make(chan bool),
		stopped: make(chan bool),
		addr:    addr,
		dir:     dir,
		log:     logrus.WithField("context", "manager"),
		client:  c,
		certs:   make(map[string]time.Time),
	}
	go m.run()
	return m, nil
}

// Add adds the specified domains to the manager.
func (m *Manager) Add(ctx context.Context, domains ...string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m.add <- domains:
		return nil
	}
}

// Remove removes the specified domains from the manager.
func (m *Manager) Remove(ctx context.Context, domains ...string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m.remove <- domains:
		return nil
	}
}

// Close the certificate manager.
func (m *Manager) Close() {
	close(m.stop)
	<-m.stopped
}
