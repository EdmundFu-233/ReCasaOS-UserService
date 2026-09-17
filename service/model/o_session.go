package model

import "time"

// RefreshSessionDBModel tracks one issued refresh token for rotation and
// revocation. The raw token is never stored; only its SHA-256 digest is kept
// so a database copy alone cannot impersonate a session.
type RefreshSessionDBModel struct {
	ID           string     `gorm:"column:id;primaryKey" json:"id"`
	UserID       int        `gorm:"column:user_id;index:idx_refresh_sessions_user" json:"user_id"`
	TokenSHA256  string     `gorm:"column:token_sha256;uniqueIndex:idx_refresh_sessions_token" json:"-"`
	IssuedAt     time.Time  `gorm:"column:issued_at" json:"issued_at"`
	ExpiresAt    time.Time  `gorm:"column:expires_at" json:"expires_at"`
	UsedAt       *time.Time `gorm:"column:used_at" json:"used_at,omitempty"`
	ReplacedBy   string     `gorm:"column:replaced_by" json:"replaced_by,omitempty"`
	RevokedAt    *time.Time `gorm:"column:revoked_at" json:"revoked_at,omitempty"`
	RevokeReason string     `gorm:"column:revoke_reason" json:"revoke_reason,omitempty"`
}

func (p *RefreshSessionDBModel) TableName() string {
	return "o_refresh_sessions"
}
