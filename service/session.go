package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/EdmundFu-233/ReCasaOS-UserService/service/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	// loginFailureLimit locks a rate-limit key after this many consecutive
	// failures; the lock lasts loginLockoutLength from the last failure and
	// is never extended by further failures.
	loginFailureLimit        = 5
	loginLockoutWindow       = time.Hour
	loginLockoutLength       = 15 * time.Minute
	loginAttemptRetention    = 24 * time.Hour
	credentialEventRetention = 180 * 24 * time.Hour
	credentialEventCap       = 100
	refreshSessionCap        = 256
	revokedAccessCap         = 1024
)

var (
	ErrRefreshSessionReused  = errors.New("refresh token was already used")
	ErrRateLimitLocked       = errors.New("credential attempts are temporarily locked")
	ErrInvalidRefreshSession = errors.New("invalid refresh session")
	ErrRefreshSigning        = errors.New("refresh token signing failed")
)

// SessionContextKey carries the verified session between the authentication
// middleware and the handlers. Both the route middleware and the v1 handlers
// use it so the session identity is never re-parsed from raw headers.
const SessionContextKey = "recasaos/user-authentication"

// AuthenticatedSession binds verified claims to the exact request that was
// authenticated. It is intentionally not inferred from source IP or proxy
// headers.
type AuthenticatedSession struct {
	Request  *http.Request
	UserID   int
	Username string
	TokenID  string
	Expires  time.Time
}

// LoginAttemptKey namespaces one failure counter. Keys use the exact
// presented username so distinct accounts never share a budget.
func LoginAttemptKey(namespace, value string) string {
	return namespace + ":" + value
}

// CreateRefreshSession records one issued refresh token. Only the SHA-256
// digest is stored; the raw token never touches the database.
func (u *userService) CreateRefreshSession(userID int, tokenSHA256 string, issuedAt, expiresAt time.Time, sessionID string) error {
	if u == nil || u.db == nil {
		return errors.New("session store is unavailable")
	}
	if userID < 1 || tokenSHA256 == "" || sessionID == "" {
		return errors.New("invalid refresh session")
	}
	return u.db.Create(&model.RefreshSessionDBModel{
		ID:          sessionID,
		UserID:      userID,
		TokenSHA256: tokenSHA256,
		IssuedAt:    issuedAt,
		ExpiresAt:   expiresAt,
	}).Error
}

// RotateRefreshSession consumes one live refresh session and records its
// replacement in a single transaction. Presenting an already-used session
// revokes the whole session family, which is the reuse-detection signal for
// a stolen refresh token. A concurrent rotation of the same session loses
// the compare-and-swap and reports the session as invalid.
func (u *userService) RotateRefreshSession(presentedSHA256, replacementID, replacementSHA256 string, issuedAt, expiresAt, now time.Time) (model.RefreshSessionDBModel, error) {
	if u == nil || u.db == nil || presentedSHA256 == "" || replacementID == "" || replacementSHA256 == "" {
		return model.RefreshSessionDBModel{}, ErrInvalidRefreshSession
	}
	var current model.RefreshSessionDBModel
	reused := false
	reusedUserID := 0
	err := u.db.Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Where("token_sha256 = ?", presentedSHA256).First(&current).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrInvalidRefreshSession
			}
			return fmt.Errorf("load refresh session: %w", err)
		}
		if current.RevokedAt != nil || !current.ExpiresAt.After(now) {
			return ErrInvalidRefreshSession
		}
		if current.UsedAt != nil {
			reused = true
			reusedUserID = current.UserID
			return ErrRefreshSessionReused
		}
		used := transaction.Model(&model.RefreshSessionDBModel{}).
			Where("id = ? AND used_at IS NULL", current.ID).
			Updates(map[string]interface{}{"used_at": now, "replaced_by": replacementID})
		if used.Error != nil {
			return fmt.Errorf("consume refresh session: %w", used.Error)
		}
		if used.RowsAffected != 1 {
			return ErrInvalidRefreshSession
		}
		current.UsedAt = &now
		current.ReplacedBy = replacementID
		return transaction.Create(&model.RefreshSessionDBModel{
			ID:          replacementID,
			UserID:      current.UserID,
			TokenSHA256: replacementSHA256,
			IssuedAt:    issuedAt,
			ExpiresAt:   expiresAt,
		}).Error
	})
	if reused {
		// The family revocation runs outside the rolled-back read
		// transaction so a replay cannot undo its own containment, and the
		// credential generation advances so a concurrent rotation that
		// committed after the revocation still cannot mint a usable token.
		revokeErr := revokeUserSessions(u.db, reusedUserID, now, "refresh token reuse detected")
		_, bumpErr := u.BumpTokenVersion(reusedUserID)
		if err := errors.Join(revokeErr, bumpErr); err != nil {
			return model.RefreshSessionDBModel{}, err
		}
		return model.RefreshSessionDBModel{}, ErrRefreshSessionReused
	}
	if err != nil {
		return model.RefreshSessionDBModel{}, err
	}
	return current, nil
}

func revokeUserSessions(db *gorm.DB, userID int, now time.Time, reason string) error {
	if err := db.Model(&model.RefreshSessionDBModel{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Updates(map[string]interface{}{"revoked_at": now, "revoke_reason": reason}).Error; err != nil {
		return fmt.Errorf("revoke user refresh sessions: %w", err)
	}
	return nil
}

// RevokeRefreshSession retires one refresh session without touching others.
func (u *userService) RevokeRefreshSession(sessionID, reason string) error {
	if u == nil || u.db == nil || sessionID == "" {
		return errors.New("invalid refresh session")
	}
	return u.db.Model(&model.RefreshSessionDBModel{}).
		Where("id = ? AND revoked_at IS NULL", sessionID).
		Updates(map[string]interface{}{"revoked_at": time.Now(), "revoke_reason": reason}).Error
}

// RevokeUserRefreshSession retires one refresh session of one user without
// touching the user's other sessions.
func (u *userService) RevokeUserRefreshSession(userID int, sessionID, reason string) error {
	if u == nil || u.db == nil || userID < 1 || sessionID == "" {
		return errors.New("invalid session revocation")
	}
	return u.db.Model(&model.RefreshSessionDBModel{}).
		Where("id = ? AND user_id = ? AND revoked_at IS NULL", sessionID, userID).
		Updates(map[string]interface{}{"revoked_at": time.Now(), "revoke_reason": reason}).Error
}

// LogoutSession retires one session: its refresh row and its access token.
// Both halves are best-effort; either one alone still fails closed.
func (u *userService) LogoutSession(userID int, sessionID string, accessExpires time.Time) error {
	if u == nil || u.db == nil || userID < 1 || sessionID == "" {
		return errors.New("invalid session logout")
	}
	revokeErr := u.RevokeUserRefreshSession(userID, sessionID, "logout")
	accessErr := u.RevokeAccessToken(sessionID, userID, accessExpires)
	return errors.Join(revokeErr, accessErr)
}

// LogoutAllSessions retires every refresh session of one user and advances
// the credential generation, which also invalidates live access tokens.
func (u *userService) LogoutAllSessions(userID int) error {
	if u == nil || u.db == nil || userID < 1 {
		return errors.New("invalid session logout")
	}
	if _, err := u.BumpTokenVersion(userID); err != nil {
		return err
	}
	return u.RevokeAllUserSessions(userID, "logout-all")
}

// ignoreMissingAuthTable drops errors from legacy databases that predate the
// session tables. Callers use it for best-effort hardening writes only; the
// authentication decision itself never depends on these writes.
func ignoreMissingAuthTable(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "no such table") || strings.Contains(err.Error(), "no such column") {
		return nil
	}
	return err
}

// RevokeAllUserSessions retires every refresh session of one user, e.g. on
// password change, explicit logout-all, or detected token reuse.
func (u *userService) RevokeAllUserSessions(userID int, reason string) error {
	if u == nil || u.db == nil || userID < 1 {
		return errors.New("invalid user session revocation")
	}
	return revokeUserSessions(u.db, userID, time.Now(), reason)
}

// BumpTokenVersion invalidates every access token minted for one user by
// advancing the credential generation the middleware compares against.
func (u *userService) BumpTokenVersion(userID int) (int, error) {
	if u == nil || u.db == nil || userID < 1 {
		return 0, errors.New("invalid token version bump")
	}
	var version int
	err := u.db.Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Model(&model.UserDBModel{}).
			Where("id = ?", userID).
			Update("token_version", gorm.Expr("token_version + 1")).Error; err != nil {
			return fmt.Errorf("advance user token version: %w", err)
		}
		var user model.UserDBModel
		if err := transaction.Select("token_version").Where("id = ?", userID).First(&user).Error; err != nil {
			return fmt.Errorf("read user token version: %w", err)
		}
		version = user.TokenVersion
		return nil
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

// GetUserTokenVersion returns the username, credential generation, and
// existence of one user for access-token validation.
func (u *userService) GetUserTokenVersion(userID int) (string, int, bool) {
	if u == nil || u.db == nil || userID < 1 {
		return "", 0, false
	}
	var user model.UserDBModel
	if err := u.db.Select("username", "token_version").Where("id = ?", userID).First(&user).Error; err != nil {
		return "", 0, false
	}
	return user.Username, user.TokenVersion, true
}

// RevokeAccessToken records one access-token identifier for rejection before
// its expiry. Rows are pruned once expired, so the set stays tiny.
func (u *userService) RevokeAccessToken(tokenID string, userID int, expiresAt time.Time) error {
	if u == nil || u.db == nil || tokenID == "" || userID < 1 {
		return errors.New("invalid access token revocation")
	}
	return u.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "jti"}},
		DoNothing: true,
	}).Create(&model.RevokedAccessTokenDBModel{
		JTI:       tokenID,
		UserID:    userID,
		ExpiresAt: expiresAt,
	}).Error
}

// IsAccessTokenRevoked reports whether one access-token identifier was
// revoked. A store error fails closed: the caller must deny the request
// rather than treat an unreadable denylist as empty.
func (u *userService) IsAccessTokenRevoked(tokenID string) (bool, error) {
	if u == nil || u.db == nil || tokenID == "" {
		return false, errors.New("access token revocation store is unavailable")
	}
	var count int64
	if err := u.db.Model(&model.RevokedAccessTokenDBModel{}).Where("jti = ?", tokenID).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// CheckLoginLockout reports whether a rate-limit key is locked and how long a
// client must wait before retrying.
func (u *userService) CheckLoginLockout(key string, now time.Time) (bool, time.Duration) {
	if u == nil || u.db == nil || key == "" {
		return false, 0
	}
	var attempt model.LoginAttemptDBModel
	if err := u.db.Where("key = ?", key).First(&attempt).Error; err != nil {
		return false, 0
	}
	if attempt.LockedUntil != nil && now.Before(*attempt.LockedUntil) {
		return true, attempt.LockedUntil.Sub(now)
	}
	return false, 0
}

// RecordLoginFailure counts one failed attempt and locks the key once the
// failure budget is exhausted. An already-locked key keeps its original
// expiry instead of extending it, so failures cannot hold a lock forever.
// A store error fails closed: the caller must not let the attempt proceed
// uncounted.
func (u *userService) RecordLoginFailure(key string, now time.Time) (bool, time.Duration, error) {
	if u == nil || u.db == nil || key == "" {
		return false, 0, errors.New("login attempt store is unavailable")
	}
	var attempt model.LoginAttemptDBModel
	locked := false
	var retryAfter time.Duration
	err := u.db.Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Where("key = ?", key).First(&attempt).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			attempt = model.LoginAttemptDBModel{Key: key, WindowStartedAt: now}
			if err := transaction.Create(&attempt).Error; err != nil {
				return err
			}
		}
		if attempt.LockedUntil != nil && now.Before(*attempt.LockedUntil) {
			locked = true
			retryAfter = attempt.LockedUntil.Sub(now)
			return nil
		}
		if attempt.WindowStartedAt.IsZero() || now.Sub(attempt.WindowStartedAt) > loginLockoutWindow {
			attempt.Failures = 0
			attempt.WindowStartedAt = now
			attempt.LockedUntil = nil
		}
		attempt.Failures++
		if attempt.Failures >= loginFailureLimit {
			until := now.Add(loginLockoutLength)
			attempt.LockedUntil = &until
			locked = true
			retryAfter = loginLockoutLength
		}
		return transaction.Save(&attempt).Error
	})
	if err != nil {
		return false, 0, err
	}
	return locked, retryAfter, nil
}

// RecordLoginSuccess clears the failure budget after a successful login.
func (u *userService) RecordLoginSuccess(key string) {
	if u == nil || u.db == nil || key == "" {
		return
	}
	_ = u.db.Where("key = ?", key).Delete(&model.LoginAttemptDBModel{}).Error
}

// LogCredentialEvent appends one auditable credential-lifecycle record.
// Callers must never include tokens, passwords, hashes, or other secrets in
// detail; tests enforce this for every recorded event type.
func (u *userService) LogCredentialEvent(actorUserID int, eventType string, success bool, source, detail string) {
	if u == nil || u.db == nil || eventType == "" {
		return
	}
	installationID := ""
	if state, err := u.GetInitializationState(context.Background()); err == nil {
		installationID = state.InstallationID
	}
	_ = u.db.Create(&model.CredentialEventDBModel{
		OccurredAt:     time.Now(),
		InstallationID: installationID,
		ActorUserID:    actorUserID,
		EventType:      eventType,
		Success:        success,
		Source:         source,
		Detail:         detail,
	}).Error
}

// ListCredentialEvents returns the most recent auditable events, newest
// first. A non-positive actor filter returns events for every user.
func (u *userService) ListCredentialEvents(actorUserID, limit int) []model.CredentialEventDBModel {
	if u == nil || u.db == nil {
		return nil
	}
	if limit <= 0 || limit > credentialEventCap {
		limit = credentialEventCap
	}
	query := u.db.Order("id DESC").Limit(limit)
	if actorUserID > 0 {
		query = query.Where("actor_user_id = ?", actorUserID)
	}
	var events []model.CredentialEventDBModel
	if err := query.Find(&events).Error; err != nil {
		return nil
	}
	return events
}

// PruneAuthState removes expired revocation and session rows, stale
// rate-limit budgets, old audit events, and per-user rows beyond the session
// and denylist caps. Consumed-but-live sessions are retained because a replay
// must still be recognized as reuse. It is best-effort by design and never
// fails authentication.
func (u *userService) PruneAuthState(now time.Time) {
	if u == nil || u.db == nil {
		return
	}
	_ = u.db.Where("expires_at < ?", now).Delete(&model.RevokedAccessTokenDBModel{}).Error
	_ = u.db.Where("expires_at < ?", now).Delete(&model.RefreshSessionDBModel{}).Error
	_ = u.db.Where("window_started_at < ? AND (locked_until IS NULL OR locked_until < ?)",
		now.Add(-loginAttemptRetention), now).Delete(&model.LoginAttemptDBModel{}).Error
	_ = u.db.Where("occurred_at < ?", now.Add(-credentialEventRetention)).Delete(&model.CredentialEventDBModel{}).Error
	_ = u.db.Exec(`DELETE FROM o_refresh_sessions WHERE id NOT IN (
		SELECT id FROM o_refresh_sessions AS kept WHERE kept.user_id = o_refresh_sessions.user_id
		ORDER BY kept.issued_at DESC, kept.id DESC LIMIT ?)`, refreshSessionCap).Error
	// The denylist cap is per user: evicting another user's live revocation
	// would resurrect their logged-out token. A user flooding their own
	// revocations only affects themselves.
	_ = u.db.Exec(`DELETE FROM o_revoked_access_tokens WHERE jti NOT IN (
		SELECT jti FROM o_revoked_access_tokens AS kept WHERE kept.user_id = o_revoked_access_tokens.user_id
		ORDER BY kept.expires_at DESC LIMIT ?)`, revokedAccessCap).Error
}
