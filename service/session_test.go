package service

import (
	"errors"
	"strconv"
	"strings"
	"sync"
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

func TestConcurrentRotationSingleWinner(t *testing.T) {
	t.Parallel()

	users := openSessionStoreTestUsers(t)
	now := time.Now()
	if err := users.CreateRefreshSession(1, "sha-first", now, now.Add(time.Hour), "session-first"); err != nil {
		t.Fatal(err)
	}
	const racers = 8
	results := make(chan error, racers)
	var running sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < racers; index++ {
		running.Add(1)
		go func(index int) {
			defer running.Done()
			<-start
			name := "session-racer-" + strconv.Itoa(index)
			_, err := users.RotateRefreshSession("sha-first", name, "sha-"+name, now, now.Add(time.Hour), now)
			results <- err
		}(index)
	}
	close(start)
	running.Wait()
	succeeded := 0
	for index := 0; index < racers; index++ {
		// Losers fail either on the compare-and-swap or on SQLite write
		// contention; both prove no double-spend happened.
		if err := <-results; err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("concurrent rotations succeeded = %d, want 1", succeeded)
	}
}

func TestPasswordChangeInvalidatesOldTokens(t *testing.T) {
	t.Parallel()

	users := openSessionStoreTestUsers(t)
	now := time.Now()
	issued, err := users.IssueLoginSession(1, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.ChangeUserPassword("1", []byte("session-store-password-01"), []byte("session-store-password-02")); err != nil {
		t.Fatalf("password change failed: %v", err)
	}
	if _, err := users.IssueRefreshedTokens(issued.RefreshToken, now); !errors.Is(err, ErrInvalidRefreshSession) {
		t.Fatalf("post-change refresh error = %v, want ErrInvalidRefreshSession", err)
	}
	if username, version, exists := users.GetUserTokenVersion(1); !exists || username != "admin" || version != 1 {
		t.Fatalf("version after change = %q, %d, %v", username, version, exists)
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
	if revoked, err := users.IsAccessTokenRevoked(first.SessionID); err != nil || revoked {
		t.Fatalf("fresh access token revoked=%v err=%v", revoked, err)
	}
	if err := users.LogoutSession(1, first.SessionID, now.Add(3*time.Hour)); err != nil {
		t.Fatalf("logout failed: %v", err)
	}
	if revoked, err := users.IsAccessTokenRevoked(first.SessionID); err != nil || !revoked {
		t.Fatalf("logged-out access token revoked=%v err=%v", revoked, err)
	}
	if revoked, err := users.IsAccessTokenRevoked(second.SessionID); err != nil || revoked {
		t.Fatalf("other session revoked=%v err=%v", revoked, err)
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
		locked, _, err := users.RecordLoginFailure(key, now)
		if err != nil {
			t.Fatal(err)
		}
		if locked {
			t.Fatalf("locked after %d failures, want 5", attempt)
		}
	}
	locked, retryAfter, err := users.RecordLoginFailure(key, now)
	if err != nil {
		t.Fatal(err)
	}
	if !locked || retryAfter <= 0 {
		t.Fatalf("fifth failure locked=%v retry=%v, want lock", locked, retryAfter)
	}
	locked, retryAfter, err = users.RecordLoginFailure(key, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !locked || retryAfter > loginLockoutLength {
		t.Fatalf("extended lock retry=%v, want at most %v", retryAfter, loginLockoutLength)
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
	if revoked, err := users.IsAccessTokenRevoked("expired-jti"); err != nil || revoked {
		t.Fatalf("expired revocation revoked=%v err=%v, want pruned", revoked, err)
	}
	if revoked, err := users.IsAccessTokenRevoked("live-jti"); err != nil || !revoked {
		t.Fatalf("live revocation revoked=%v err=%v, want retained", revoked, err)
	}
}
