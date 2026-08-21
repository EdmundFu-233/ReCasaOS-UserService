// Package password implements the password formats accepted by the user service.
// New passwords are always encoded as bounded Argon2id PHC strings. The legacy
// unsalted MD5 format is accepted only so a successful login can migrate it.
package password

import (
	"crypto/md5" // #nosec G501 -- legacy verification only; never used for new password storage.
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	Version = 19

	DefaultMemory      uint32 = 64 * 1024
	DefaultIterations  uint32 = 3
	DefaultParallelism uint8  = 4
	DefaultSaltLength         = 16
	DefaultKeyLength          = 32

	MinMemory      uint32 = 19 * 1024
	MaxMemory      uint32 = 128 * 1024
	MinIterations  uint32 = 1
	MaxIterations  uint32 = 5
	MinParallelism uint8  = 1
	MaxParallelism uint8  = 8
	MinSaltLength         = 16
	MaxSaltLength         = 64
	MinKeyLength          = 16
	MaxKeyLength          = 64
)

var (
	ErrInvalidHash = errors.New("invalid password hash")
	ErrPassword    = errors.New("password does not match")
	argon2Gate     = make(chan struct{}, 1)
)

type Parameters struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  int
	KeyLength   int
}

var defaultParameters = Parameters{
	Memory:      DefaultMemory,
	Iterations:  DefaultIterations,
	Parallelism: DefaultParallelism,
	SaltLength:  DefaultSaltLength,
	KeyLength:   DefaultKeyLength,
}

type parsedHash struct {
	parameters Parameters
	salt       []byte
	digest     []byte
}

func Hash(plaintext []byte) (string, error) {
	return hashWithReader(plaintext, defaultParameters, rand.Reader)
}

func hashWithReader(plaintext []byte, parameters Parameters, random io.Reader) (string, error) {
	if err := validateParameters(parameters); err != nil {
		return "", err
	}

	salt := make([]byte, parameters.SaltLength)
	if _, err := io.ReadFull(random, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	digest := deriveKey(plaintext, salt, parameters, parameters.KeyLength)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		Version,
		parameters.Memory,
		parameters.Iterations,
		parameters.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

// Verify accepts bounded Argon2id PHC strings and the exact legacy lowercase
// MD5 representation. A true legacy result means callers must migrate with a
// compare-and-swap update before treating the migration as complete.
func Verify(encoded string, plaintext []byte) (legacy bool, err error) {
	if isLegacyMD5(encoded) {
		sum := md5.Sum(plaintext) // #nosec G401 -- compatibility check followed by an Argon2id migration.
		expected := make([]byte, md5.Size)
		if _, decodeErr := hex.Decode(expected, []byte(encoded)); decodeErr != nil {
			return false, ErrInvalidHash
		}
		if subtle.ConstantTimeCompare(sum[:], expected) != 1 {
			return true, ErrPassword
		}
		return true, nil
	}

	parsed, err := parse(encoded)
	if err != nil {
		return false, err
	}
	digest := deriveKey(plaintext, parsed.salt, parsed.parameters, len(parsed.digest))
	if subtle.ConstantTimeCompare(digest, parsed.digest) != 1 {
		return false, ErrPassword
	}
	return false, nil
}

// ConsumeUnknownUser performs the same bounded Argon2id work as a normal
// login, reducing the username-existence timing signal. The result is ignored.
func ConsumeUnknownUser(plaintext []byte) {
	parameters := defaultParameters
	_ = deriveKey(plaintext, []byte("ReCasaOS-dummy-v1"), parameters, parameters.KeyLength)
}

func deriveKey(plaintext, salt []byte, parameters Parameters, keyLength int) []byte {
	argon2Gate <- struct{}{}
	defer func() { <-argon2Gate }()
	return argon2.IDKey(plaintext, salt, parameters.Iterations, parameters.Memory, parameters.Parallelism, uint32(keyLength))
}

func NeedsRehash(encoded string) bool {
	parsed, err := parse(encoded)
	if err != nil {
		return true
	}
	return parsed.parameters != defaultParameters
}

func IsArgon2id(encoded string) bool {
	_, err := parse(encoded)
	return err == nil
}

func parse(encoded string) (parsedHash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return parsedHash{}, ErrInvalidHash
	}

	parameterParts := strings.Split(parts[3], ",")
	if len(parameterParts) != 3 || !strings.HasPrefix(parameterParts[0], "m=") || !strings.HasPrefix(parameterParts[1], "t=") || !strings.HasPrefix(parameterParts[2], "p=") {
		return parsedHash{}, ErrInvalidHash
	}
	memory, err := parseUint(parameterParts[0][2:], 32)
	if err != nil {
		return parsedHash{}, ErrInvalidHash
	}
	iterations, err := parseUint(parameterParts[1][2:], 32)
	if err != nil {
		return parsedHash{}, ErrInvalidHash
	}
	parallelism, err := parseUint(parameterParts[2][2:], 8)
	if err != nil {
		return parsedHash{}, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return parsedHash{}, ErrInvalidHash
	}
	digest, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return parsedHash{}, ErrInvalidHash
	}

	parameters := Parameters{
		Memory:      uint32(memory),
		Iterations:  uint32(iterations),
		Parallelism: uint8(parallelism),
		SaltLength:  len(salt),
		KeyLength:   len(digest),
	}
	if err := validateParameters(parameters); err != nil {
		return parsedHash{}, ErrInvalidHash
	}

	return parsedHash{parameters: parameters, salt: salt, digest: digest}, nil
}

func parseUint(value string, bits int) (uint64, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, ErrInvalidHash
	}
	return strconv.ParseUint(value, 10, bits)
}

func validateParameters(parameters Parameters) error {
	if parameters.Memory < MinMemory || parameters.Memory > MaxMemory ||
		parameters.Iterations < MinIterations || parameters.Iterations > MaxIterations ||
		parameters.Parallelism < MinParallelism || parameters.Parallelism > MaxParallelism ||
		parameters.SaltLength < MinSaltLength || parameters.SaltLength > MaxSaltLength ||
		parameters.KeyLength < MinKeyLength || parameters.KeyLength > MaxKeyLength {
		return ErrInvalidHash
	}
	return nil
}

func isLegacyMD5(encoded string) bool {
	if len(encoded) != md5.Size*2 {
		return false
	}
	for _, character := range encoded {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
