package password

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- constructs a legacy fixture only.
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

var fastTestParameters = Parameters{
	Memory:      MinMemory,
	Iterations:  MinIterations,
	Parallelism: MinParallelism,
	SaltLength:  MinSaltLength,
	KeyLength:   MinKeyLength,
}

func TestArgon2idRoundTrip(t *testing.T) {
	plaintext := []byte("correct horse battery staple")
	encoded, err := hashWithReader(plaintext, fastTestParameters, bytes.NewReader(bytes.Repeat([]byte{0x42}, MinSaltLength)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=19456,t=1,p=1$") {
		t.Fatalf("unexpected PHC string: %q", encoded)
	}
	legacy, err := Verify(encoded, plaintext)
	if err != nil || legacy {
		t.Fatalf("Verify() = legacy %v, err %v", legacy, err)
	}
	if _, err := Verify(encoded, []byte("wrong password")); !errors.Is(err, ErrPassword) {
		t.Fatalf("wrong password error = %v", err)
	}
	if !NeedsRehash(encoded) {
		t.Fatal("non-default parameters must request rehash")
	}
}

func TestHashUsesIndependentSalts(t *testing.T) {
	plaintext := []byte("correct horse battery staple")
	first, err := Hash(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Hash(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("password hashes unexpectedly reused a salt")
	}
	if !IsArgon2id(first) || NeedsRehash(first) {
		t.Fatal("default hash is not a current Argon2id encoding")
	}
}

func TestLegacyMD5VerificationIsMigrationOnly(t *testing.T) {
	plaintext := []byte("legacy-password")
	digest := md5.Sum(plaintext) // #nosec G401 -- legacy fixture.
	encoded := hex.EncodeToString(digest[:])

	legacy, err := Verify(encoded, plaintext)
	if err != nil || !legacy {
		t.Fatalf("Verify() = legacy %v, err %v", legacy, err)
	}
	if _, err := Verify(encoded, []byte("wrong")); !errors.Is(err, ErrPassword) {
		t.Fatalf("wrong legacy password error = %v", err)
	}
	if _, err := Verify(strings.ToUpper(encoded), plaintext); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("uppercase legacy hash should be rejected, got %v", err)
	}
	if !NeedsRehash(encoded) || IsArgon2id(encoded) {
		t.Fatal("legacy hash was mistaken for Argon2id")
	}
}

func TestPHCParserRejectsUnboundedAndNonCanonicalInputs(t *testing.T) {
	valid, err := hashWithReader(
		[]byte("correct horse battery staple"),
		fastTestParameters,
		bytes.NewReader(bytes.Repeat([]byte{0x24}, MinSaltLength)),
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []string{
		"",
		"$argon2i$v=19$m=19456,t=1,p=1$JCQkJCQkJCQkJCQkJCQkJA$JCQkJCQkJCQkJCQkJCQkJA",
		strings.Replace(valid, "v=19", "v=16", 1),
		strings.Replace(valid, "m=19456", "m=19455", 1),
		strings.Replace(valid, "m=19456", "m=131073", 1),
		strings.Replace(valid, "t=1", "t=6", 1),
		strings.Replace(valid, "p=1", "p=9", 1),
		strings.Replace(valid, "m=19456", "m=019456", 1),
		strings.Replace(valid, "m=19456,t=1,p=1", "t=1,m=19456,p=1", 1),
		valid + "$extra",
		strings.Replace(valid, "$JCQkJCQkJCQkJCQkJCQkJA$", "$eA$", 1),
		strings.Replace(valid, "JCQkJCQkJCQkJCQkJCQkJA", "JCQkJCQkJCQkJCQkJCQkJA=", 1),
	}
	for _, encoded := range tests {
		if _, err := Verify(encoded, []byte("irrelevant")); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("Verify(%q) error = %v, want ErrInvalidHash", encoded, err)
		}
	}
}

func TestHashReportsRandomnessFailure(t *testing.T) {
	_, err := hashWithReader([]byte("password"), fastTestParameters, failingReader{})
	if err == nil || !strings.Contains(err.Error(), "generate password salt") {
		t.Fatalf("Hash() error = %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}
