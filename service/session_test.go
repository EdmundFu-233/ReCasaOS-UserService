package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/authsecurity"
	passwordutil "github.com/EdmundFu-233/ReCasaOS-UserService/pkg/password"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/sqlite"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/userbootstrap"
	"github.com/EdmundFu-233/ReCasaOS-UserService/service/model"
)

func openSessionStoreTestUsers(t *testing.T) UserService {
	t.Helper()
	db, err := sqlite.GetDb(t.TempDir() + "/db")
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	users := NewUserService(db, userbootstrap.State{InstallationID: "test-installation"})
	if users == nil {
		t.Fatal("test user service is unavailable")
	}
	hash, err := passwordutil.Hash([]byte("session-store-password-01"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.UserDBModel{Username: "admin", Password: string(hash), Role: "admin"}).Error; err != nil {
		t.Fatal(err)
	}
	return users
}

func TestRotateRefreshSessionRoundTrip(t *testing.T) {
	t.Parallel()

	users := openSessionStoreTestUsers(t)
	now := time.Now()
	if err := users.CreateRefreshSession(1, "sha-first", now, now.Add(time.Hour), "session-first"); err != nil {
		t.Fatal(err)
	}
	current, err := users.RotateRefreshSession("sha-first", "session-second", "sha-second", now, now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	if current.ID != "session-first" || current.UserID != 1 {
		t.Fatalf("rotated session = %+v", current)
	}
	rotated, err := users.RotateRefreshSession("sha-second", "session-third", "sha-third", now, now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("second rotation failed: %v", err)
	}
	if rotated.ID != "session-second" || rotated.ReplacedBy != "session-third" {
		t.Fatalf("second rotation = %+v", rotated)
	}
}

func TestRotateRefreshSessionReuseRevokesFamily(t *testing.T) {
	t.Parallel()

	users := openSessionStoreTestUsers(t)
	now := time.Now()
	if err := users.CreateRefreshSession(1, "sha-first", now, now.Add(time.Hour), "session-first"); err != nil {
		t.Fatal(err)
	}
	if _, err := users.RotateRefreshSession("sha-first", "session-second", "sha-second", now, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := users.RotateRefreshSession("sha-first", "session-attacker", "sha-attacker", now, now.Add(time.Hour), now); !errors.Is(err, ErrRefreshSessionReused) {
		t.Fatalf("replay error = %v, want ErrRefreshSessionReused", err)
	}
	// The whole family, including the rotated session, is now revoked.
	if _, err := users.RotateRefreshSession("sha-second", "session-third", "sha-third", now, now.Add(time.Hour), now); !errors.Is(err, ErrInvalidRefreshSession) {
		t.Fatalf("post-reuse rotation error = %v, want ErrInvalidRefreshSession", err)
	}
}

func TestRotateRefreshSessionRejectsUnknownExpiredAndRevoked(t *testing.T) {
	t.Parallel()

	users := openSessionStoreTestUsers(t)
	now := time.Now()
	if _, err := users.RotateRefreshSession("sha-missing", "session-x", "sha-x", now, now.Add(time.Hour), now); !errors.Is(err, ErrInvalidRefreshSession) {
		t.Fatalf("unknown session error = %v, want ErrInvalidRefreshSession", err)
	}
	if err := users.CreateRefreshSession(1, "sha-old", now.Add(-2*time.Hour), now.Add(-time.Hour), "session-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := users.RotateRefreshSession("sha-old", "session-x", "sha-x", now, now.Add(time.Hour), now); !errors.Is(err, ErrInvalidRefreshSession) {
		t.Fatalf("expired session error = %v, want ErrInvalidRefreshSession", err)
	}
	if err := users.CreateRefreshSession(1, "sha-doomed", now, now.Add(time.Hour), "session-doomed"); err != nil {
		t.Fatal(err)
	}
	if err := users.RevokeRefreshSession("session-doomed", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := users.RotateRefreshSession("sha-doomed", "session-x", "sha-x", now, now.Add(time.Hour), now); !errors.Is(err, ErrInvalidRefreshSession) {
		t.Fatalf("revoked session error = %v, want ErrInvalidRefreshSession", err)
	}
}

func TestBumpTokenVersionInvalidatesOldGeneration(t *testing.T) {
	t.Parallel()

	users := openSessionStoreTestUsers(t)
	username, version, exists := users.GetUserTokenVersion(1)
	if !exists || username != "admin" || version != 0 {
		t.Fatalf("initial version = %q, %d, %v", username, version, exists)
	}
	next, err := users.BumpTokenVersion(1)
	if err != nil || next != 1 {
		t.Fatalf("bumped version = %d, %v", next, err)
	}
	if _, _, exists := users.GetUserTokenVersion(999); exists {
		t.Fatal("unknown user reported a version")
	}
}

func TestLogoutSessionAndLogoutAll(t *testing.T) {
	t.Parallel()

	users := openSessionStoreTestUsers(t)
	now := time.Now()
	first, err := users.IssueLoginSession(1, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := users.IssueLoginSession(1, now)
	if err != nil {
		t.Fatal(err)
	}
	if users.IsAccessTokenRevoked(first.SessionID) {
		t.Fatal("fresh access token reported revoked")
	}
	if err := users.LogoutSession(1, first.SessionID, now.Add(3*time.Hour)); err != nil {
		t.Fatalf("logout failed: %v", err)
	}
	if !users.IsAccessTokenRevoked(first.SessionID) {
		t.Fatal("logged-out access token still accepted")
	}
	if users.IsAccessTokenRevoked(second.SessionID) {
		t.Fatal("other session was revoked by single logout")
	}
	if err := users.LogoutAllSessions(1); err != nil {
		t.Fatalf("logout-all failed: %v", err)
	}
	if _, version, _ := users.GetUserTokenVersion(1); version != 1 {
		t.Fatalf("logout-all version = %d, want 1", version)
	}
	// The remaining refresh session was revoked with the family: the version
	// bump already invalidates its access token, and rotation now fails.
	if _, err := users.RotateRefreshSession(
		authsecurity.TokenSHA256(second.RefreshToken), "session-after-logout-all", "sha-after-logout-all",
		now, now.Add(time.Hour), now,
	); !errors.Is(err, ErrInvalidRefreshSession) {
		t.Fatalf("post-logout-all rotation error = %v, want ErrInvalidRefreshSession", err)
	}
}

func TestLoginLockoutLifecycle(t *testing.T) {
	t.Parallel()

	users := openSessionStoreTestUsers(t)
	now := time.Now()
	key := LoginAttemptKey("login", "admin")
	for attempt := 1; attempt <= 4; attempt++ {
		locked, _ := users.RecordLoginFailure(key, now)
		if locked {
			t.Fatalf("locked after %d failures, want 5", attempt)
		}
	}
	locked, retryAfter := users.RecordLoginFailure(key, now)
	if !locked || retryAfter <= 0 {
		t.Fatalf("fifth failure locked=%v retry=%v, want lock", locked, retryAfter)
	}
	if locked, _ := users.CheckLoginLockout(key, now); !locked {
		t.Fatal("lockout not reported")
	}
	if locked, _ := users.CheckLoginLockout(key, now.Add(16*time.Minute)); locked {
		t.Fatal("lockout did not expire")
	}
	users.RecordLoginSuccess(key)
	if locked, _ := users.CheckLoginLockout(key, now); locked {
		t.Fatal("success did not clear the budget")
	}
}

func TestCredentialEventsContainNoSecrets(t *testing.T) {
	t.Parallel()

	users := openSessionStoreTestUsers(t)
	now := time.Now()
	first, err := users.IssueLoginSession(1, now)
	if err != nil {
		t.Fatal(err)
	}
	users.LogCredentialEvent(1, model.CredentialEventLoginSuccess, true, "login", "")
	users.LogCredentialEvent(0, model.CredentialEventLoginFailure, false, "login", "")
	if err := users.LogoutSession(1, first.SessionID, now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	users.LogCredentialEvent(1, model.CredentialEventLogout, true, "logout", "")
	events := users.ListCredentialEvents(0, 100)
	if len(events) < 3 {
		t.Fatalf("events = %d, want at least 3", len(events))
	}
	for _, event := range events {
		joined := event.EventType + "\x00" + event.Detail + "\x00" + event.Source
		for _, forbidden := range []string{
			"session-store-password-01", first.AccessToken, first.RefreshToken,
			"eyJ", "$argon2", "password",
		} {
			if forbidden != "" && strings.Contains(joined, forbidden) {
				t.Fatalf("event %d leaks secret material: %q", event.ID, joined)
			}
		}
		if event.OccurredAt.IsZero() {
			t.Fatalf("event %d has no timestamp", event.ID)
		}
	}
	// Actor filtering returns only that actor's events.
	own := users.ListCredentialEvents(1, 100)
	for _, event := range own {
		if event.ActorUserID != 1 {
			t.Fatalf("actor filter leaked event %+v", event)
		}
	}
}

func TestPruneAuthStateRemovesOnlyExpiredRows(t *testing.T) {
	t.Parallel()

	users := openSessionStoreTestUsers(t)
	now := time.Now()
	if err := users.RevokeAccessToken("expired-jti", 1, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := users.RevokeAccessToken("live-jti", 1, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	users.PruneAuthState(now)
	if users.IsAccessTokenRevoked("expired-jti") {
		t.Fatal("expired revocation was not pruned")
	}
	if !users.IsAccessTokenRevoked("live-jti") {
		t.Fatal("live revocation was pruned")
	}
}
