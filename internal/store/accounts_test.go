package store

import "testing"

// Real installations hash with OWASP's count; only test binaries use fewer.
func TestPasswordIterations(t *testing.T) {
	if productionPasswordIterations < 600_000 {
		t.Fatalf("production PBKDF2 iterations %d are below OWASP's 600,000", productionPasswordIterations)
	}
	if passwordIterations >= productionPasswordIterations {
		t.Fatalf("tests hash with %d iterations; expected fewer", passwordIterations)
	}
	// A hash made by a real installation still verifies.
	encoded := hashPasswordWith([]byte("correct horse battery"), make([]byte, 16), productionPasswordIterations)
	if !checkPassword(encoded, []byte("correct horse battery")) {
		t.Fatal("a production-strength hash did not verify correctly")
	}
}
