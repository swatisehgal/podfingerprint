/*
 * Copyright 2022 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package podfingerprint

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type podIdent struct {
	Namespace string
	Name      string
}

func (pi podIdent) GetNamespace() string {
	return pi.Namespace
}

func (pi podIdent) GetName() string {
	return pi.Name
}

var stressPods []podIdent

var pods []podIdent
var podsErr error

const (
	clusterMaxNodes       = 5000
	clusterMaxPodsPerNode = 300
)

const (
	stressNamespaceLen = 52
	stressNameLen      = 72
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func init() {
	var data []byte
	data, podsErr = os.ReadFile(filepath.Join("testdata", "pods.json"))
	if podsErr != nil {
		return
	}
	podsErr = json.Unmarshal(data, &pods)

	stressPodsCount := clusterMaxNodes * clusterMaxPodsPerNode
	for idx := 0; idx < stressPodsCount; idx++ {
		stressPods = append(stressPods, podIdent{
			Namespace: RandStringBytes(stressNamespaceLen),
			Name:      RandStringBytes(stressNameLen),
		})
	}
}

func TestVersionCompatible(t *testing.T) {
	type testCase struct {
		version        string
		expectedError  error
		expectedCompat bool
	}

	testCases := []testCase{
		{
			version:       "",
			expectedError: ErrMalformed,
		},
		{
			version:       "a", // shorter than expected
			expectedError: ErrMalformed,
		},
		{
			version:        "xxxx", // long as expected
			expectedCompat: false,
		},
		{
			version:       "bbbbbbbb", // longer than expected
			expectedError: ErrMalformed,
		},
		{
			version:        Version,
			expectedCompat: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.version, func(t *testing.T) {
			got, err := IsVersionCompatible(tc.version)
			if err != tc.expectedError {
				t.Errorf("error got %v expected %v", err, tc.expectedError)
			}
			if got != tc.expectedCompat {
				t.Errorf("compat got %v expected %v", got, tc.expectedCompat)
			}
		})
	}
}

func TestSumPod(t *testing.T) {
	if len(pods) == 0 || podsErr != nil {
		t.Fatalf("cannot load the test data: %v", podsErr)
	}

	fp := NewFingerprint(len(pods))
	for _, pod := range pods {
		fp.AddPod(&pod)
	}
	x := fp.Sum()
	if len(x) == 0 {
		t.Fatalf("zero-lenght sum")
	}
}

func TestSumPodStable(t *testing.T) {
	if len(pods) == 0 || podsErr != nil {
		t.Fatalf("cannot load the test data: %v", podsErr)
	}

	localPods := make([]podIdent, len(pods))
	copy(localPods, pods)
	rand.Shuffle(len(localPods), func(i, j int) {
		localPods[i], localPods[j] = localPods[j], localPods[i]
	})

	fp := &Fingerprint{}
	for _, pod := range pods {
		fp.AddPod(&pod)
	}
	fp2 := &Fingerprint{}
	for _, localPod := range localPods {
		fp2.Add(localPod.Namespace, localPod.Name)
	}

	x := fp.Sum()
	x2 := fp2.Sum()
	if !reflect.DeepEqual(x, x2) {
		t.Fatalf("signature not stable: %x vs %x", x, x2)
	}
}

func TestSum(t *testing.T) {
	if len(pods) == 0 || podsErr != nil {
		t.Fatalf("cannot load the test data: %v", podsErr)
	}

	fp := NewFingerprint(len(pods))
	for _, pod := range pods {
		fp.Add(pod.Namespace, pod.Name)
	}
	x := fp.Sum()
	if len(x) == 0 {
		t.Fatalf("zero-lenght sum")
	}
}

func TestSumStable(t *testing.T) {
	if len(pods) == 0 || podsErr != nil {
		t.Fatalf("cannot load the test data: %v", podsErr)
	}

	localPods := make([]podIdent, len(pods))
	copy(localPods, pods)
	rand.Shuffle(len(localPods), func(i, j int) {
		localPods[i], localPods[j] = localPods[j], localPods[i]
	})

	fp := &Fingerprint{}
	for _, pod := range pods {
		fp.Add(pod.Namespace, pod.Name)
	}
	fp2 := &Fingerprint{}
	for _, localPod := range localPods {
		fp2.Add(localPod.Namespace, localPod.Name)
	}

	x := fp.Sum()
	x2 := fp2.Sum()
	if !reflect.DeepEqual(x, x2) {
		t.Fatalf("signature not stable: %x vs %x", x, x2)
	}
}

func TestSign(t *testing.T) {
	if len(pods) == 0 || podsErr != nil {
		t.Fatalf("cannot load the test data: %v", podsErr)
	}

	localPods := make([]podIdent, len(pods))
	copy(localPods, pods)
	rand.Shuffle(len(localPods), func(i, j int) {
		localPods[i], localPods[j] = localPods[j], localPods[i]
	})

	fp := &Fingerprint{}
	for _, pod := range pods {
		fp.Add(pod.Namespace, pod.Name)
	}
	fp2 := &Fingerprint{}
	for _, localPod := range localPods {
		fp2.Add(localPod.Namespace, localPod.Name)
	}

	x := fp.Sign()
	x2 := fp2.Sign()
	if x != x2 {
		t.Fatalf("signature not stable: %q vs %q", x, x2)
	}
}

func TestCheck(t *testing.T) {
	type testCase struct {
		description   string
		pods          []podIdent
		fingerprint   string
		expectedError error
	}

	testCases := []testCase{
		{
			description:   "too short",
			pods:          pods,
			fingerprint:   "x",
			expectedError: ErrMalformed,
		},
		{
			description:   "wrong prefix",
			pods:          pods,
			fingerprint:   "wrngv001e477a4e3b2fc0ec6",
			expectedError: ErrMalformed,
		},
		{
			// artificial test case
			description:   "malformed version",
			pods:          pods,
			fingerprint:   "pfp0vX",
			expectedError: ErrMalformed,
		},
		{
			description:   "incompatible version",
			pods:          pods,
			fingerprint:   "pfp0v000e477a4e3b2fc0ec6",
			expectedError: ErrIncompatibleVersion,
		},
		{
			description:   "wrong fingerprint",
			pods:          pods,
			fingerprint:   "pfp0v001e477abb123fc0ec1",
			expectedError: ErrSignatureMismatch,
		},
		{
			description: "correct fingerprint",
			pods:        pods,
			fingerprint: "pfp0v001d2cea00aa866782a", // precomputed and validated manually
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			fp := NewFingerprint(len(tc.pods))
			for _, pod := range tc.pods {
				fp.Add(pod.Namespace, pod.Name)
			}
			err := fp.Check(tc.fingerprint)
			if err != nil && !errors.Is(err, tc.expectedError) {
				t.Errorf("unexpected error: %v expected %v (fingerprint %q expected %q)", err, tc.expectedError, fp.Sign(), tc.fingerprint)
			}
		})
	}
}

func benchHelper(maxNodes, maxPodsPerNode int) {
	var fps []*Fingerprint
	for nIdx := 0; nIdx < maxNodes; nIdx++ {
		fp := NewFingerprint(maxPodsPerNode)
		fps = append(fps, fp)
		for pIdx := 0; pIdx < maxPodsPerNode; pIdx++ {
			stressPod := &stressPods[(maxPodsPerNode*nIdx)+pIdx]
			fp.AddPod(stressPod)
		}
		_ = fp.Sum()
	}
}

func BenchmarkFingerprint(b *testing.B) {
	benchmarks := []struct {
		maxNodes       int
		maxPodsPerNode int
	}{
		{3, 32},
		{3, 64},
		{3, 128},
		{3, 256},
		{3, 300},
		{10, 32},
		{10, 64},
		{10, 128},
		{10, 256},
		{10, 300},
		{100, 32},
		{100, 64},
		{100, 128},
		{100, 256},
		{100, 300},
		{1000, 32},
		{1000, 64},
		{1000, 128},
		{1000, 256},
		{1000, 300},
		{5000, 32},
		{5000, 64},
		{5000, 128},
		{5000, 256},
		{5000, 300},
	}
	for _, bm := range benchmarks {
		name := fmt.Sprintf("nodes=%d podsPerNode=%d", bm.maxNodes, bm.maxPodsPerNode)
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				benchHelper(bm.maxNodes, bm.maxPodsPerNode)
			}
		})
	}
}
