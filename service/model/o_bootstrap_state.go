package model

import "time"

// BootstrapStateDBModel is a durable singleton. Once it leaves pristine state,
// deleting users or restoring an empty user table can only enter recovery; it
// can never silently reopen setup.
type BootstrapStateDBModel struct {
	ID             uint8      `gorm:"column:id;primaryKey;check:id = 1"`
	InstallationID string     `gorm:"column:installation_id;not null"`
	Status         string     `gorm:"column:status;not null"`
	AdminUserID    *int64     `gorm:"column:admin_user_id"`
	InitializedAt  *time.Time `gorm:"column:initialized_at"`
	CreatedAt      time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt      time.Time  `gorm:"column:updated_at;autoUpdateTime"`
}

func (BootstrapStateDBModel) TableName() string {
	return "o_bootstrap_state"
}
