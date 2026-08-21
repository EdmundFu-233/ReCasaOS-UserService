// Package userbootstrap provides the exactly-once transition from an
// uninitialized appliance to one with a local administrator. A database marker
// is paired with an installation seal stored outside the database backup tree,
// so restoring only user.db can never silently reopen setup.
package userbootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	passwordutil "github.com/EdmundFu-233/ReCasaOS-UserService/pkg/password"
)

const singletonID = 1

type Status string

const (
	StatusPristine    Status = "pristine"
	StatusInitialized Status = "initialized"
	StatusRecovery    Status = "recovery"
)

var (
	ErrAlreadyInitialized = errors.New("user service is already initialized")
	ErrRecoveryRequired   = errors.New("user bootstrap is locked and requires local recovery")
	ErrInconsistentState  = errors.New("user bootstrap state is inconsistent")
)

type State struct {
	InstallationID string
	Status         Status
}

func (state State) Initialized() bool {
	return state.Status == StatusInitialized
}

func (state State) SetupRequired() bool {
	return state.Status == StatusPristine
}

// Seal is an integrity marker stored outside the database directory.
type Seal interface {
	Load() (installationID string, exists bool, err error)
	Create(installationID string) error
}

// ReconcileState imports legacy installations and applies the fail-closed
// restore state machine. The database transition is committed before a missing
// seal is created. Thus a crash can leave only "initialized DB, missing seal",
// which is safely repairable without creating another user.
func ReconcileState(ctx context.Context, db *sql.DB, seal Seal) (State, error) {
	if seal == nil {
		return State{}, errors.New("bootstrap seal is required")
	}
	sealID, sealExists, err := seal.Load()
	if err != nil {
		return State{}, fmt.Errorf("load bootstrap seal: %w", err)
	}

	newID, err := newInstallationID()
	if err != nil {
		return State{}, err
	}
	var result State
	createSeal := false
	recovery := false
	err = withImmediateTransaction(ctx, db, func(conn *sql.Conn) error {
		marker, exists, err := readState(ctx, conn)
		if err != nil {
			return err
		}
		userCount, firstUserID, err := userSummary(ctx, conn)
		if err != nil {
			return err
		}
		now := time.Now().UTC()

		if !exists {
			switch {
			case sealExists:
				result = State{InstallationID: sealID, Status: StatusRecovery}
				recovery = true
			case userCount > 0:
				result = State{InstallationID: newID, Status: StatusInitialized}
				createSeal = true
			default:
				result = State{InstallationID: newID, Status: StatusPristine}
			}
			if err := insertState(ctx, conn, result, firstUserID, now); err != nil {
				return err
			}
			return nil
		}

		result = marker
		if !validInstallationID(marker.InstallationID) || !validStatus(marker.Status) {
			result.InstallationID = newID
			if sealExists {
				result.InstallationID = sealID
			}
			result.Status = StatusRecovery
			recovery = true
			return updateState(ctx, conn, result, firstUserID, now)
		}

		switch marker.Status {
		case StatusRecovery:
			recovery = true
		case StatusPristine:
			switch {
			case sealExists:
				result.Status = StatusRecovery
				recovery = true
			case userCount > 0:
				result.Status = StatusInitialized
				createSeal = true
			}
		case StatusInitialized:
			switch {
			case userCount == 0:
				result.Status = StatusRecovery
				recovery = true
			case sealExists && sealID != marker.InstallationID:
				result.Status = StatusRecovery
				recovery = true
			case !sealExists:
				createSeal = true
			}
		}

		if result.Status != marker.Status {
			if err := updateState(ctx, conn, result, firstUserID, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return State{}, err
	}

	if createSeal {
		if err := seal.Create(result.InstallationID); err != nil {
			return State{}, fmt.Errorf("create bootstrap seal: %w", err)
		}
	}
	if recovery {
		return result, ErrRecoveryRequired
	}
	return result, nil
}

// CreateAdmin inserts the first administrator and seals setup in one SQLite
// BEGIN IMMEDIATE transaction. The password must already be a strong verifier.
// beforeCommit may create required local resources; returning an error rolls
// back every database change.
func CreateAdmin(ctx context.Context, db *sql.DB, seal Seal, username, passwordHash string, beforeCommit func(userID int64) error) (int64, error) {
	if !passwordutil.IsArgon2id(passwordHash) {
		return 0, errors.New("bootstrap password must be an Argon2id verifier")
	}
	state, err := ReconcileState(ctx, db, seal)
	if err != nil {
		return 0, err
	}
	if state.Status != StatusPristine {
		return 0, ErrAlreadyInitialized
	}

	var createdUserID int64
	var outcome error
	err = withImmediateTransaction(ctx, db, func(conn *sql.Conn) error {
		marker, exists, err := readState(ctx, conn)
		if err != nil {
			return err
		}
		userCount, _, err := userSummary(ctx, conn)
		if err != nil {
			return err
		}
		if !exists || marker.Status != StatusPristine || marker.InstallationID != state.InstallationID || userCount != 0 {
			outcome = ErrAlreadyInitialized
			return nil
		}

		now := time.Now().UTC()
		result, err := conn.ExecContext(ctx, `INSERT INTO o_users
			(username, password, role, created_at, updated_at) VALUES (?, ?, 'admin', ?, ?)`, username, passwordHash, now, now)
		if err != nil {
			return fmt.Errorf("create bootstrap administrator: %w", err)
		}
		createdUserID, err = result.LastInsertId()
		if err != nil {
			return fmt.Errorf("read bootstrap administrator id: %w", err)
		}
		if createdUserID < 1 {
			return errors.New("read bootstrap administrator id: invalid id")
		}

		if beforeCommit != nil {
			if err := beforeCommit(createdUserID); err != nil {
				return fmt.Errorf("prepare administrator data: %w", err)
			}
		}

		result, err = conn.ExecContext(ctx, `UPDATE o_bootstrap_state
			SET status = ?, admin_user_id = ?, initialized_at = ?, updated_at = ?
			WHERE id = ? AND installation_id = ? AND status = ?`,
			StatusInitialized, createdUserID, now, now, singletonID, state.InstallationID, StatusPristine)
		if err != nil {
			return fmt.Errorf("seal bootstrap database state: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("read bootstrap transition result: %w", err)
		}
		if rows != 1 {
			return ErrInconsistentState
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if outcome != nil {
		_, reconcileErr := ReconcileState(ctx, db, seal)
		if reconcileErr != nil {
			return 0, reconcileErr
		}
		return 0, outcome
	}

	// This deliberately occurs after COMMIT. If it fails or the process dies,
	// ReconcileState recreates only the missing seal for the same installation.
	if err := seal.Create(state.InstallationID); err != nil {
		return 0, fmt.Errorf("create bootstrap seal after database commit: %w", err)
	}
	return createdUserID, nil
}

func readState(ctx context.Context, conn *sql.Conn) (State, bool, error) {
	var state State
	err := conn.QueryRowContext(ctx, `SELECT installation_id, status FROM o_bootstrap_state WHERE id = ?`, singletonID).
		Scan(&state.InstallationID, &state.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, fmt.Errorf("read bootstrap state: %w", err)
	}
	return state, true, nil
}

func insertState(ctx context.Context, conn *sql.Conn, state State, adminUserID *int64, now time.Time) error {
	var initializedAt *time.Time
	if state.Status == StatusInitialized {
		initializedAt = &now
	}
	_, err := conn.ExecContext(ctx, `INSERT INTO o_bootstrap_state
		(id, installation_id, status, admin_user_id, initialized_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, singletonID, state.InstallationID, state.Status, adminUserID, initializedAt, now, now)
	if err != nil {
		return fmt.Errorf("create bootstrap state: %w", err)
	}
	return nil
}

func updateState(ctx context.Context, conn *sql.Conn, state State, adminUserID *int64, now time.Time) error {
	var initializedAt *time.Time
	if state.Status == StatusInitialized {
		initializedAt = &now
	}
	result, err := conn.ExecContext(ctx, `UPDATE o_bootstrap_state
		SET installation_id = ?, status = ?, admin_user_id = ?, initialized_at = ?, updated_at = ? WHERE id = ?`,
		state.InstallationID, state.Status, adminUserID, initializedAt, now, singletonID)
	if err != nil {
		return fmt.Errorf("update bootstrap state: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read bootstrap state update result: %w", err)
	}
	if rows != 1 {
		return ErrInconsistentState
	}
	return nil
}

func userSummary(ctx context.Context, conn *sql.Conn) (count int64, firstUserID *int64, err error) {
	var nullableID sql.NullInt64
	err = conn.QueryRowContext(ctx, `SELECT COUNT(*), MIN(id) FROM o_users`).Scan(&count, &nullableID)
	if err != nil {
		return 0, nil, fmt.Errorf("read user summary: %w", err)
	}
	if nullableID.Valid {
		id := nullableID.Int64
		firstUserID = &id
	}
	return count, firstUserID, nil
}

func withImmediateTransaction(ctx context.Context, db *sql.DB, operation func(*sql.Conn) error) (err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire database connection: %w", err)
	}
	defer conn.Close()

	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("begin immediate transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	if err = operation(conn); err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("commit immediate transaction: %w", err)
	}
	committed = true
	return nil
}

func newInstallationID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate installation id: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func validInstallationID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := value[0:8] + value[9:13] + value[14:18] + value[19:23] + value[24:36]
	decoded, err := hex.DecodeString(compact)
	return err == nil && len(decoded) == 16 && value[14] == '4' && (value[19] == '8' || value[19] == '9' || value[19] == 'a' || value[19] == 'b')
}

func validStatus(status Status) bool {
	return status == StatusPristine || status == StatusInitialized || status == StatusRecovery
}
