package platform

import "testing"

func TestDetectAlpine(t *testing.T) {
	got, err := Detect("NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.22.1\nPRETTY_NAME=\"Alpine Linux v3.22\"\n")
	if err != nil || got.Family != Alpine || got.Codename != "v3.22" || got.Major != 3 || got.Minor != 22 {
		t.Fatalf("Detect = %+v, %v", got, err)
	}
	for _, old := range []string{"3.17.5", "2.7.0"} {
		if _, err := Detect("ID=alpine\nVERSION_ID=" + old + "\n"); err == nil {
			t.Errorf("Alpine %s should be unsupported", old)
		}
	}
}
