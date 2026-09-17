package model

import "time"

// Credential event types recorded in o_credential_events. Handlers and tests
// must never place tokens, passwords, hashes, or other secrets in Detail.
const (
	CredentialEventLoginSuccess     = "login_success"
	CredentialEventLoginFailure     = "login_failure"
	CredentialEventLoginLockout     = "login_lockout"
	CredentialEventLogout           = "logout"
	CredentialEventLogoutAll        = "logout_all"
	CredentialEventRefreshSuccess   = "refresh_success"
	CredentialEventRefreshFailure   = "refresh_failure"
	CredentialEventRefreshReuse     = "refresh_reuse_detected"
	CredentialEventPasswordChanged  = "password_changed"
	CredentialEventPasswordReset    = "password_reset"
	CredentialEventBootstrapCreated = "bootstrap_admin_created"
)

// CredentialEventDBModel is an append-only, auditable record of credential
// lifecycle operations. It contains identities and outcomes only; secrets
// must never be written here.
type CredentialEventDBModel struct {
	ID             int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	OccurredAt     time.Time `gorm:"column:occurred_at;index:idx_credential_events_time" json:"occurred_at"`
	InstallationID string    `gorm:"column:installation_id" json:"installation_id,omitempty"`
	ActorUserID    int       `gorm:"column:actor_user_id;index:idx_credential_events_actor" json:"actor_user_id"`
	EventType      string    `gorm:"column:event_type;index:idx_credential_events_type" json:"event_type"`
	Success        bool      `gorm:"column:success" json:"success"`
	Source         string    `gorm:"column:source" json:"source"`
	Detail         string    `gorm:"column:detail" json:"detail,omitempty"`
}

func (p *CredentialEventDBModel) TableName() string {
	return "o_credential_events"
}
