package hooksign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type Store struct {
	mu          sync.RWMutex
	Users       map[string]*User
	UsersByID   map[string]*User
	Partners    map[string]*Partner
	Events      map[string]*Event
	EventOrder  []string
	nextEventID int
}

func NewStore() *Store {
	s := &Store{
		Users:     make(map[string]*User),
		UsersByID: make(map[string]*User),
		Partners:  make(map[string]*Partner),
		Events:    make(map[string]*Event),
	}
	s.seed()
	return s
}

func (s *Store) seed() {
	admin := &User{ID: "admin-001", Name: "Admin", Role: "admin", APIKey: "admin-key-001"}
	alice := &User{ID: "user-001", Name: "Alice", Role: "partner_owner", APIKey: "user-key-001"}
	bob := &User{ID: "user-002", Name: "Bob", Role: "partner_owner", APIKey: "user-key-002"}
	carol := &User{ID: "user-003", Name: "Carol", Role: "partner_owner", APIKey: "user-key-003"}

	for _, u := range []*User{admin, alice, bob, carol} {
		s.Users[u.APIKey] = u
		s.UsersByID[u.ID] = u
	}

	now := time.Now().Add(-24 * time.Hour)
	s.Partners["stripe-mock"] = &Partner{
		Name:      "stripe-mock",
		Owner:     "user-001",
		Secret:    "whsec_alpha_a1b2c3d4e5f6",
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.Partners["github-mock"] = &Partner{
		Name:      "github-mock",
		Owner:     "user-002",
		Secret:    "whsec_beta_b2c3d4e5f6a1",
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.Partners["slack-mock"] = &Partner{
		Name:      "slack-mock",
		Owner:     "user-003",
		Secret:    "whsec_gamma_c3d4e5f6a1b2",
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func (s *Store) nextID() string {
	s.nextEventID++
	return fmt.Sprintf("evt-%d", s.nextEventID)
}

// computeSignature returns the canonical hex HMAC-SHA256 of the
// canonical string "timestamp.body" using the partner secret.
func computeSignature(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", timestamp)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
