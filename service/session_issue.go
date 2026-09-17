package service

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/authsecurity"
	"github.com/EdmundFu-233/ReCasaOS-UserService/service/model"
)

// IssuedSession is one minted access/refresh pair bound to a tracked refresh
// session. Both tokens share the session identifier as their jti claim, so a
// single logout can retire the pair.
type IssuedSession struct {
	User         model.UserDBModel
	SessionID    string
	AccessToken  string
	RefreshToken string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

// IssueLoginSession mints an access/refresh pair for an already-authenticated
// user and records the refresh session. The caller authenticates first.
func (u *userService) IssueLoginSession(userID int, now time.Time) (IssuedSession, error) {
	if u == nil || u.db == nil || userID < 1 {
		return IssuedSession{}, errors.New("invalid login session request")
	}
	var user model.UserDBModel
	if err := u.db.Where("id = ?", userID).First(&user).Error; err != nil {
		return IssuedSession{}, fmt.Errorf("load user for session issuance: %w", err)
	}
	issued, err := u.issueSessionPair(user, now)
	if err != nil {
		return IssuedSession{}, err
	}
	u.PruneAuthState(now)
	return issued, nil
}

// IssueRefreshedTokens validates one refresh token, rotates its session, and
// mints a replacement pair. Reusing an already-consumed token revokes the
// whole session family and reports the session as reused.
func (u *userService) IssueRefreshedTokens(presented string, now time.Time) (IssuedSession, error) {
	if u == nil || u.db == nil || presented == "" {
		return IssuedSession{}, ErrInvalidRefreshSession
	}
	if u.privateKey == nil || u.publicKey == nil {
		return IssuedSession{}, ErrRefreshSigning
	}
	claims, err := authsecurity.ValidateSessionRefreshToken(presented, u.publicKeyFunc())
	if err != nil {
		return IssuedSession{}, ErrInvalidRefreshSession
	}
	lockKey := LoginAttemptKey("refresh", strconv.Itoa(claims.UserID))
	if locked, _ := u.CheckLoginLockout(lockKey, now); locked {
		return IssuedSession{}, ErrRateLimitLocked
	}
	var user model.UserDBModel
	if err := u.db.Where("id = ?", claims.UserID).First(&user).Error; err != nil {
		if _, _, recordErr := u.RecordLoginFailure(lockKey, now); recordErr != nil {
			return IssuedSession{}, recordErr
		}
		return IssuedSession{}, ErrInvalidRefreshSession
	}
	if user.Username != claims.Username || user.TokenVersion != claims.TokenVersion {
		if _, _, recordErr := u.RecordLoginFailure(lockKey, now); recordErr != nil {
			return IssuedSession{}, recordErr
		}
		return IssuedSession{}, ErrInvalidRefreshSession
	}
	replacementID, err := authsecurity.NewTokenID()
	if err != nil {
		return IssuedSession{}, ErrInvalidRefreshSession
	}
	replacementRefresh, err := authsecurity.MintRefreshToken(user.Username, user.Id, user.TokenVersion, replacementID, u.privateKey)
	if err != nil {
		return IssuedSession{}, ErrRefreshSigning
	}
	replacementAccess, err := authsecurity.MintAccessToken(user.Username, user.Id, user.TokenVersion, replacementID, u.privateKey)
	if err != nil {
		return IssuedSession{}, ErrRefreshSigning
	}
	if _, err := u.RotateRefreshSession(
		authsecurity.TokenSHA256(presented),
		replacementID,
		authsecurity.TokenSHA256(replacementRefresh),
		now,
		now.Add(authsecurity.RefreshTokenLifetime),
		now,
	); err != nil {
		if errors.Is(err, ErrRefreshSessionReused) {
			return IssuedSession{}, ErrRefreshSessionReused
		}
		if _, _, recordErr := u.RecordLoginFailure(lockKey, now); recordErr != nil {
			return IssuedSession{}, recordErr
		}
		return IssuedSession{}, ErrInvalidRefreshSession
	}
	u.RecordLoginSuccess(lockKey)
	u.PruneAuthState(now)
	return IssuedSession{
		User:         user,
		SessionID:    replacementID,
		AccessToken:  replacementAccess,
		RefreshToken: replacementRefresh,
		IssuedAt:     now,
		ExpiresAt:    now.Add(authsecurity.AccessTokenLifetime),
	}, nil
}

func (u *userService) publicKeyFunc() func() (*ecdsa.PublicKey, error) {
	return func() (*ecdsa.PublicKey, error) {
		if u == nil || u.publicKey == nil {
			return nil, errors.New("signing key is unavailable")
		}
		return u.publicKey, nil
	}
}

func (u *userService) issueSessionPair(user model.UserDBModel, now time.Time) (IssuedSession, error) {
	sessionID, err := authsecurity.NewTokenID()
	if err != nil {
		return IssuedSession{}, err
	}
	access, err := authsecurity.MintAccessToken(user.Username, user.Id, user.TokenVersion, sessionID, u.privateKey)
	if err != nil {
		return IssuedSession{}, ErrRefreshSigning
	}
	refresh, err := authsecurity.MintRefreshToken(user.Username, user.Id, user.TokenVersion, sessionID, u.privateKey)
	if err != nil {
		return IssuedSession{}, ErrRefreshSigning
	}
	expiresAt := now.Add(authsecurity.RefreshTokenLifetime)
	if err := u.CreateRefreshSession(user.Id, authsecurity.TokenSHA256(refresh), now, expiresAt, sessionID); err != nil {
		return IssuedSession{}, err
	}
	return IssuedSession{
		User:         user,
		SessionID:    sessionID,
		AccessToken:  access,
		RefreshToken: refresh,
		IssuedAt:     now,
		ExpiresAt:    now.Add(authsecurity.AccessTokenLifetime),
	}, nil
}
