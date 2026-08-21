package password

import (
	"bytes"
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
	if err := Verify(encoded, plaintext); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if err := Verify(encoded, []byte("wrong password")); !errors.Is(err, ErrPassword) {
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

func TestLegacyWeakVerifierIsRejected(t *testing.T) {
	// Known legacy digest for "legacy-password". The test intentionally uses a
	// fixed vector so no weak hash implementation is linked into the service.
	const legacyVerifier = "12121b2b7fdedd5ec5777926650d7119"
	if err := Verify(legacyVerifier, []byte("legacy-password")); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("Verify() error = %v; want strict rejection", err)
	}
	if !NeedsRehash(legacyVerifier) || IsArgon2id(legacyVerifier) {
		t.Fatal("legacy verifier was mistaken for Argon2id")
	}
}

func TestEveryRejectedCredentialPathPerformsExactlyOneKDF(t *testing.T) {
	valid, err := hashWithReader(
		[]byte("correct horse battery staple"),
		fastTestParameters,
		bytes.NewReader(bytes.Repeat([]byte{0x35}, MinSaltLength)),
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		run  func(deriveKeyFunction) error
	}{
		{
			name: "malformed stored verifier",
			run: func(derive deriveKeyFunction) error {
				return verifyWithDeriver("12121b2b7fdedd5ec5777926650d7119", []byte("candidate"), derive)
			},
		},
		{
			name: "wrong Argon2id password",
			run: func(derive deriveKeyFunction) error {
				return verifyWithDeriver(valid, []byte("wrong"), derive)
			},
		},
		{
			name: "missing user",
			run: func(derive deriveKeyFunction) error {
				consumeUnknownUserWithDeriver([]byte("candidate"), derive)
				return ErrPassword
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			derive := func(_ []byte, _ []byte, _ Parameters, keyLength int) []byte {
				calls++
				return make([]byte, keyLength)
			}
			if err := test.run(derive); err == nil {
				t.Fatal("rejected credential path unexpectedly succeeded")
			}
			if calls != 1 {
				t.Fatalf("KDF calls = %d, want 1", calls)
			}
		})
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
		if err := Verify(encoded, []byte("irrelevant")); !errors.Is(err, ErrInvalidHash) {
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
