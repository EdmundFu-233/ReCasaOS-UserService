package model

import "time"

// RevokedAccessTokenDBModel records access-token identifiers that must be
// rejected before their expiry, e.g. after a single-session logout. Rows are
// pruned once they expire; the table is expected to stay tiny.
type RevokedAccessTokenDBModel struct {
	JTI       string    `gorm:"column:jti;primaryKey" json:"-"`
	UserID    int       `gorm:"column:user_id" json:"user_id"`
	ExpiresAt time.Time `gorm:"column:expires_at;index:idx_revoked_access_expiry" json:"expires_at"`
}

func (p *RevokedAccessTokenDBModel) TableName() string {
	return "o_revoked_access_tokens"
}
