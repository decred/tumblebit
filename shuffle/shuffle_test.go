// Copyright 2009 The Go Authors. All rights reserved.
// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shuffle

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"testing"
)

func TestPanicOnNegativeLenght(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("didn't panic")
		}
	}()
	Shuffle(rand.New(rand.NewSource(1)), -1, func(i, j int) {})
}

func TestPanicOnLengthTooLarge(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("didn't panic")
		}
	}()
	Shuffle(rand.New(rand.NewSource(1)), 1<<31-1, func(i, j int) {})
}

func TestZeroLegthShuffle(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatal("paniced on zero length")
		}
	}()
	Shuffle(rand.New(rand.NewSource(1)), 0, func(i, j int) {})
}

func TestSingleElementShuffle(t *testing.T) {
	a := []int{1}
	Shuffle(rand.New(rand.NewSource(1)), len(a), func(i, j int) {
		a[i], a[j] = a[j], a[i]
	})
	if len(a) > 1 || a[0] != 1 {
		t.Fatal("data damage")
	}
}

func TestTwoElementShuffle(t *testing.T) {
	a := [...]int{0, 1}
	Shuffle(rand.New(rand.NewSource(1)), len(a), func(i, j int) {
		a[i], a[j] = a[j], a[i]
	})
	if !(a == [...]int{0, 1} || a == [...]int{1, 0}) {
		t.Fatal("data damage")
	}
}

func TestSimpleShuffleSort(t *testing.T) {
	r := rand.New(rand.NewSource(1))

	for size := 10; size < 1000; size += 10 + r.Intn(50) {
		a := make([]int, size)
		for i := range a {
			a[i] = i
		}
		half := make([]int, size/2)
		for i := range half {
			half[i] = i
		}
		full := make([]int, size)
		for i := range full {
			full[i] = i
		}

		s := Shuffle(r, len(a), func(i, j int) {
			a[i], a[j] = a[j], a[i]
		})

		// Sort elements in half and full according to the permutation
		// created by the shuffle.

		sort.Slice(half, func(i, j int) bool {
			return s.Get(half[i]) < s.Get(half[j])
		})
		checkHalf := make([]int, size/2)
		k := 0
		for i := range a {
			for j := range checkHalf {
				if a[i] == j {
					checkHalf[k] = a[i]
					k++
					break
				}
			}
		}
		for i := range half {
			if half[i] != checkHalf[i] {
				t.Fatalf("bad sort for half size of %d", size)
			}
		}

		sort.Slice(full, func(i, j int) bool {
			return s.Get(full[i]) < s.Get(full[j])
		})
		for i := range full {
			if full[i] != a[i] {
				t.Fatalf("bad sort for full size of %d", size)
			}
		}
	}
}

func TestUniformFactorial(t *testing.T) {
	r := rand.New(rand.NewSource(10))
	top := 6
	if testing.Short() {
		top = 4
	}
	for n := 3; n <= top; n++ {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			// Calculate n!.
			nfact := 1
			for i := 2; i <= n; i++ {
				nfact *= i
			}

			// Test a few different ways to generate a uniform distribution.
			p := make([]int, n) // re-usable slice for Shuffle generator
			tests := [...]struct {
				name string
				fn   func() int
			}{
				{name: "uniformRandom31", fn: func() int {
					return int(uniformRandom31(r, int32(nfact)))
				}},
				{name: "Shuffle", fn: func() int {
					// Generate permutation using Shuffle.
					for i := range p {
						p[i] = i
					}
					Shuffle(r, n, func(i, j int) {
						p[i], p[j] = p[j], p[i]
					})
					return encodePerm(p)
				}},
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					// Gather chi-squared values and check that they follow
					// the expected normal distribution given n!-1 degrees of freedom.
					// See https://en.wikipedia.org/wiki/Pearson%27s_chi-squared_test and
					// https://www.johndcook.com/Beautiful_Testing_ch10.pdf.
					nsamples := 10 * nfact
					if nsamples < 200 {
						nsamples = 200
					}
					samples := make([]float64, nsamples)
					for i := range samples {
						// Generate some uniformly distributed values and count their occurrences.
						const iters = 1000
						counts := make([]int, nfact)
						for i := 0; i < iters; i++ {
							counts[test.fn()]++
						}
						// Calculate chi-squared and add to samples.
						want := iters / float64(nfact)
						var χ2 float64
						for _, have := range counts {
							err := float64(have) - want
							χ2 += err * err
						}
						χ2 /= want
						samples[i] = χ2
					}

					// Check that our samples approximate the appropriate normal distribution.
					dof := float64(nfact - 1)
					expected := &statsResults{mean: dof, stddev: math.Sqrt(2 * dof)}
					errorScale := max(1.0, expected.stddev)
					expected.closeEnough = 0.10 * errorScale
					expected.maxError = 0.08 // TODO: What is the right value here? See issue 21211.
					checkSampleDistribution(t, samples, expected)
				})
			}
		})
	}
}

type statsResults struct {
	mean        float64
	stddev      float64
	closeEnough float64
	maxError    float64
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func nearEqual(a, b, closeEnough, maxError float64) bool {
	absDiff := math.Abs(a - b)
	if absDiff < closeEnough { // Necessary when one value is zero and one value is close to zero.
		return true
	}
	return absDiff/max(math.Abs(a), math.Abs(b)) < maxError
}

// checkSimilarDistribution returns success if the mean and stddev of the
// two statsResults are similar.
func (this *statsResults) checkSimilarDistribution(expected *statsResults) error {
	if !nearEqual(this.mean, expected.mean, expected.closeEnough, expected.maxError) {
		s := fmt.Sprintf("mean %v != %v (allowed error %v, %v)", this.mean, expected.mean, expected.closeEnough, expected.maxError)
		fmt.Println(s)
		return errors.New(s)
	}
	if !nearEqual(this.stddev, expected.stddev, expected.closeEnough, expected.maxError) {
		s := fmt.Sprintf("stddev %v != %v (allowed error %v, %v)", this.stddev, expected.stddev, expected.closeEnough, expected.maxError)
		fmt.Println(s)
		return errors.New(s)
	}
	return nil
}

func getStatsResults(samples []float64) *statsResults {
	res := new(statsResults)
	var sum, squaresum float64
	for _, s := range samples {
		sum += s
		squaresum += s * s
	}
	res.mean = sum / float64(len(samples))
	res.stddev = math.Sqrt(squaresum/float64(len(samples)) - res.mean*res.mean)
	return res
}

func checkSampleDistribution(t *testing.T, samples []float64, expected *statsResults) {
	t.Helper()
	actual := getStatsResults(samples)
	err := actual.checkSimilarDistribution(expected)
	if err != nil {
		t.Errorf(err.Error())
	}
}

// encodePerm converts from a permuted slice of length n, such as Perm generates, to an int in [0, n!).
// See https://en.wikipedia.org/wiki/Lehmer_code.
// encodePerm modifies the input slice.
func encodePerm(s []int) int {
	// Convert to Lehmer code.
	for i, x := range s {
		r := s[i+1:]
		for j, y := range r {
			if y > x {
				r[j]--
			}
		}
	}
	// Convert to int in [0, n!).
	m := 0
	fact := 1
	for i := len(s) - 1; i >= 0; i-- {
		m += s[i] * fact
		fact *= len(s) - i
	}
	return m
}
