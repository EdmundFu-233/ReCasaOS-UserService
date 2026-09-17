package model

import "time"

// LoginAttemptDBModel records consecutive authentication failures for one
// rate-limit key ("login:<username>" or "refresh:<user id>"). A sustained
// failure run locks the key until LockedUntil; a success clears the row.
type LoginAttemptDBModel struct {
	Key             string     `gorm:"column:key;primaryKey" json:"-"`
	Failures        int        `gorm:"column:failures" json:"failures"`
	WindowStartedAt time.Time  `gorm:"column:window_started_at" json:"window_started_at"`
	LockedUntil     *time.Time `gorm:"column:locked_until" json:"locked_until,omitempty"`
}

func (p *LoginAttemptDBModel) TableName() string {
	return "o_login_attempts"
}
