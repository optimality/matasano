package challenge6

import "testing"

func TestHammingDistance(t *testing.T) {
	input1 := []byte("this is a test")
	input2 := []byte("wokka wokka!!!")
	expected := 37
	actual, err := HammingDistance(input1, input2)
	if err != nil {
		t.Errorf("Error in HammingDistance: %v\n", err)
	}
	if expected != actual {
		t.Errorf("Expected: %v\nActual: %v\n", expected, actual)
	}
}
