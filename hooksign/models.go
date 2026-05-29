package hooksign

import "time"

type User struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Role   string `json:"role"`
	APIKey string `json:"-"`
}

type Partner struct {
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Event struct {
	ID         string    `json:"id"`
	Partner    string    `json:"partner"`
	DeliveryID string    `json:"delivery_id"`
	Timestamp  int64     `json:"timestamp"`
	Body       string    `json:"body"`
	Signature  string    `json:"signature"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}
