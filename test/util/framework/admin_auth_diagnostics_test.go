// Copyright 2026 Microsoft Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package framework

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"

	hcpdiscovery "github.com/Azure/ARO-HCP/tooling/hcpctl/pkg/hcp"
)

func newTestAuthDiagnostics(t *testing.T) (*AdminCredentialDiagnostics, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "observations.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	close(done)
	d := &AdminCredentialDiagnostics{
		ctx: ctx, cancel: cancel, done: done, start: time.Now().UTC(),
		duration: 500 * time.Millisecond, interval: 5 * time.Millisecond,
		logger: logr.Discard(), kube: fake.NewClientset(), namespace: "hcp",
		file: file, encoder: json.NewEncoder(file),
		previous: map[string]string{}, failures: map[string]error{},
	}
	t.Cleanup(func() { _ = d.Close() })
	return d, path
}

func readAuthDiagnosticEvents(t *testing.T, path string) []authDiagnosticEvent {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var events []authDiagnosticEvent
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var event authDiagnosticEvent
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		require.False(t, event.ObservedAt.IsZero())
		events = append(events, event)
	}
	return events
}

func TestAdminAuthDiagnosticsDisabled(t *testing.T) {
	t.Setenv(adminAuthDiagnosticKubeconfig, "")
	tc := &perItOrDescribeTestContext{}
	d, err := tc.StartAdminCredentialDiagnostics(t.Context(), "managed")
	require.NoError(t, err)
	require.Nil(t, d)
	original := errors.New("initial viability failure")
	require.Same(t, original, d.Finish(t.Context(), nil, original))
	require.NoError(t, d.Close())
}

func TestAdminAuthDiagnosticsInvalidSetup(t *testing.T) {
	t.Setenv(adminAuthDiagnosticKubeconfig, filepath.Join(t.TempDir(), "missing-kubeconfig"))
	tc := &perItOrDescribeTestContext{}
	_, err := tc.StartAdminCredentialDiagnostics(t.Context(), "managed")
	require.ErrorContains(t, err, "requires ARTIFACT_DIR")
	tc.LogDirPath = t.TempDir()
	_, err = tc.StartAdminCredentialDiagnostics(t.Context(), "managed")
	require.ErrorContains(t, err, "load auth diagnostic management kubeconfig")
}

func TestAdminAuthDiagnosticNamespace(t *testing.T) {
	clusters := []hcpdiscovery.HCPInfo{
		{SubscriptionID: "different", ResourceGroupName: "managed", Namespace: "wrong-subscription"},
		{SubscriptionID: "sub", ResourceGroupName: "managed-suffix", Namespace: "wrong-group"},
		{SubscriptionID: "SUB", ResourceGroupName: "MANAGED", Namespace: "correct-cluster"},
	}
	namespace, err := authDiagnosticNamespace(clusters, "sub", "managed")
	require.NoError(t, err)
	require.Equal(t, "correct-cluster", namespace)
	_, err = authDiagnosticNamespace(clusters, "missing", "managed")
	require.ErrorContains(t, err, "not present yet")
	clusters = append(clusters, clusters[2])
	_, err = authDiagnosticNamespace(clusters, "sub", "managed")
	require.ErrorContains(t, err, "multiple HostedClusters")
}

func TestAdminAuthDiagnosticsMountedCACommand(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "kubectl")
	arguments := filepath.Join(directory, "arguments")
	t.Setenv("AUTH_DIAGNOSTIC_TEST_ARGUMENTS", arguments)
	t.Setenv("AUTH_DIAGNOSTIC_TEST_BUNDLE", "public CA bundle")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$AUTH_DIAGNOSTIC_TEST_ARGUMENTS\"\nprintf '%s' \"$AUTH_DIAGNOSTIC_TEST_BUNDLE\"\n"), 0700))
	bundle, err := readAuthDiagnosticMountedCA(t.Context(), binary, "/secure/management.kubeconfig", "hcp", "kas")
	require.NoError(t, err)
	require.Equal(t, "public CA bundle", string(bundle))
	data, err := os.ReadFile(arguments)
	require.NoError(t, err)
	require.Equal(t, []string{
		"--kubeconfig", "/secure/management.kubeconfig", "--namespace", "hcp",
		"exec", "kas", "--container", "kube-apiserver", "--", "cat", "/etc/kubernetes/certs/client-ca/ca.crt",
	}, strings.Split(strings.TrimSpace(string(data)), "\n"))
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\necho 'exec denied' >&2\nexit 1\n"), 0700))
	_, err = readAuthDiagnosticMountedCA(t.Context(), binary, "/secure/management.kubeconfig", "hcp", "kas")
	require.ErrorContains(t, err, "exec denied")
}

func TestAdminAuthDiagnosticsReplicaBundles(t *testing.T) {
	currentCA, _, err := certutil.GenerateSelfSignedCertKey("current", nil, nil)
	require.NoError(t, err)
	oldCA, _, err := certutil.GenerateSelfSignedCertKey("old", nil, nil)
	require.NoError(t, err)
	d, path := newTestAuthDiagnostics(t)
	d.kube = fake.NewClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "client-ca", Namespace: "hcp", ResourceVersion: "42"}, Data: map[string]string{"ca.crt": string(currentCA)}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "ready", Namespace: "hcp", Labels: map[string]string{"app": "kube-apiserver"}}, Spec: corev1.PodSpec{NodeName: "node-1"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "lagging", Namespace: "hcp", Labels: map[string]string{"app": "kube-apiserver"}}, Spec: corev1.PodSpec{NodeName: "node-2"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "unreadable", Namespace: "hcp", Labels: map[string]string{"app": "kube-apiserver"}}},
	)
	recovered := false
	d.readCA = func(_ context.Context, namespace, pod string) ([]byte, error) {
		require.Equal(t, "hcp", namespace)
		switch {
		case pod == "unreadable" && !recovered:
			return nil, errors.New("pods/exec forbidden")
		case pod == "lagging" && !recovered:
			return oldCA, nil
		default:
			return currentCA, nil
		}
	}
	d.sample()
	recovered = true
	d.sample()
	require.NoError(t, d.Close())
	events := readAuthDiagnosticEvents(t, path)
	currentHash, _, err := authDiagnosticCertificates(currentCA)
	require.NoError(t, err)
	oldHash, _, err := authDiagnosticCertificates(oldCA)
	require.NoError(t, err)
	var laggingHashes []string
	var sawForbidden, sawConfigMap bool
	for _, event := range events {
		if event.Source == "configmap" {
			sawConfigMap = true
			require.Equal(t, "42", event.ResourceVersion)
			require.Equal(t, currentHash, event.BundleSHA256)
		}
		if event.Pod == "lagging" {
			laggingHashes = append(laggingHashes, event.BundleSHA256)
			require.Equal(t, "node-2", event.Node)
		}
		sawForbidden = sawForbidden || strings.Contains(event.Error, "pods/exec forbidden")
	}
	require.True(t, sawConfigMap)
	require.True(t, sawForbidden, "failed collection must be visible, not look like a matching bundle")
	require.Equal(t, []string{oldHash, currentHash}, laggingHashes)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(data), "BEGIN CERTIFICATE")
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestAdminAuthDiagnosticsInvalidBundleAndPersistentCollectionError(t *testing.T) {
	hash, certificates, err := authDiagnosticCertificates([]byte("not a certificate"))
	require.Error(t, err)
	require.Len(t, hash, 64)
	require.Empty(t, certificates)
	d, path := newTestAuthDiagnostics(t)
	d.record(authDiagnosticEvent{Source: "mounted-ca", Pod: "unreadable"}, errors.New("exec denied"))
	require.ErrorContains(t, d.Close(), "exec denied")
	require.ErrorContains(t, d.Close(), "exec denied", "close must be idempotent")
	require.Equal(t, "exec denied", readAuthDiagnosticEvents(t, path)[0].Error)
}

func TestAdminAuthDiagnosticsObserverStopsBeforeCleanup(t *testing.T) {
	certificate, _, err := certutil.GenerateSelfSignedCertKey("customer", nil, nil)
	require.NoError(t, err)
	d, path := newTestAuthDiagnostics(t)
	d.namespace = ""
	d.discover = func(context.Context) (string, error) { return "hcp", nil }
	d.kube = fake.NewClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "client-ca", Namespace: "hcp"}, Data: map[string]string{"ca.crt": string(certificate)}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kas", Namespace: "hcp", Labels: map[string]string{"app": "kube-apiserver"}}},
	)
	sampled := make(chan struct{})
	reads := 0
	d.readCA = func(context.Context, string, string) ([]byte, error) {
		reads++
		if reads == 2 {
			close(sampled)
		}
		return certificate, nil
	}
	d.done = make(chan struct{})
	go func() {
		defer close(d.done)
		d.run()
	}()
	for range 20 {
		d.record(authDiagnosticEvent{Source: "guest-probe", HTTPStatus: 200}, nil)
	}
	select {
	case <-sampled:
	case <-time.After(5 * time.Second):
		t.Fatal("observer did not sample the mounted CA")
	}
	require.NoError(t, d.Close())
	select {
	case <-d.done:
	default:
		t.Fatal("observer is still running after close")
	}
	var sources []string
	for _, event := range readAuthDiagnosticEvents(t, path) {
		sources = append(sources, event.Source)
	}
	require.Contains(t, sources, "namespace")
	require.Contains(t, sources, "configmap")
	require.Contains(t, sources, "mounted-ca")
	require.Contains(t, sources, "guest-probe")
}

func TestAdminAuthDiagnosticsPreservesFailureAfterSameCertificateRecovers(t *testing.T) {
	certificate, key, err := certutil.GenerateSelfSignedCertKey("customer", nil, nil)
	require.NoError(t, err)
	var mu sync.Mutex
	var serials []string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		serials = append(serials, r.TLS.PeerCertificates[0].SerialNumber.String())
		count := len(serials)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if count <= 2 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Unauthorized","message":"Unauthorized","code":401}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"kind":"ServiceList","apiVersion":"v1","items":[]}`)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	config := &rest.Config{
		Host: server.URL,
		TLSClientConfig: rest.TLSClientConfig{
			CAData:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
			CertData: certificate, KeyData: key,
		},
	}
	d, path := newTestAuthDiagnostics(t)
	original := errors.New("initial viability check: Unauthorized")
	require.ErrorIs(t, d.Finish(t.Context(), config, original), original)
	var statuses []int
	var fingerprint string
	for _, event := range readAuthDiagnosticEvents(t, path) {
		if event.Source == "guest-probe" {
			statuses = append(statuses, event.HTTPStatus)
		}
		if event.Source == "credential" {
			require.NotEmpty(t, event.Certificates)
			fingerprint = event.Certificates[0].SHA256
		}
	}
	require.GreaterOrEqual(t, len(statuses), 3)
	require.Equal(t, []int{401, 401, 200}, statuses[:3])
	require.Len(t, fingerprint, 64)
	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(serials), 3)
	for _, serial := range serials {
		require.Equal(t, serials[0], serial, "diagnostics must not fetch or replace credentials")
	}
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(data), string(key))
	require.NotContains(t, string(data), "PRIVATE KEY")
}

func TestAdminAuthDiagnosticsCanceledProbe(t *testing.T) {
	certificate, key, err := certutil.GenerateSelfSignedCertKey("customer", nil, nil)
	require.NoError(t, err)
	d, _ := newTestAuthDiagnostics(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	config := &rest.Config{Host: "https://127.0.0.1:1", TLSClientConfig: rest.TLSClientConfig{CertData: certificate, KeyData: key}}
	require.ErrorIs(t, d.probeCredential(ctx, config), context.Canceled)
}

func TestAdminAuthDiagnosticsFilteredServerLogs(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint("failure=", fail), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/pods") {
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprint(w, `{"kind":"PodList","apiVersion":"v1","items":[{"metadata":{"name":"kas","namespace":"hcp"}}]}`)
					return
				}
				if fail {
					http.Error(w, "log access denied", http.StatusForbidden)
					return
				}
				require.Equal(t, "kube-apiserver", r.URL.Query().Get("container"))
				require.Equal(t, "true", r.URL.Query().Get("timestamps"))
				require.NotEmpty(t, r.URL.Query().Get("sinceTime"))
				_, _ = fmt.Fprintln(w, "unrelated log that must not be persisted")
				_, _ = fmt.Fprintln(w, `2026-11-17T00:06:40Z Unable to authenticate the request: unknown authority`)
				_, _ = fmt.Fprintln(w, `2026-11-17T00:06:50Z Loaded a new CA Bundle and Verifier`)
			}))
			defer server.Close()
			d, path := newTestAuthDiagnostics(t)
			kube, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
			require.NoError(t, err)
			d.kube = kube
			err = d.collectLogs(t.Context())
			if fail {
				require.Error(t, err)
				require.Error(t, d.Close())
			} else {
				require.NoError(t, err)
				require.NoError(t, d.Close())
			}
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NotContains(t, string(data), "unrelated log")
			if fail {
				require.Contains(t, string(data), `"error":`)
			} else {
				require.Contains(t, string(data), "unknown authority")
				require.Contains(t, string(data), "Loaded a new CA Bundle")
			}
		})
	}
}

func TestAdminAuthDiagnosticsWriteFailureStopsObserver(t *testing.T) {
	d, _ := newTestAuthDiagnostics(t)
	require.NoError(t, d.file.Close())
	d.record(authDiagnosticEvent{Source: "configmap"}, nil)
	require.Error(t, d.ctx.Err())
	require.Error(t, d.Close())
}

func TestAdminAuthDiagnosticsLogLimitIsExplicit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"kind":"PodList","apiVersion":"v1","items":[{"metadata":{"name":"kas","namespace":"hcp"}}]}`)
			return
		}
		_, _ = fmt.Fprint(w, strings.Repeat("x", adminAuthDiagnosticLogLimit))
	}))
	defer server.Close()
	d, path := newTestAuthDiagnostics(t)
	kube, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	require.NoError(t, err)
	d.kube = kube
	require.ErrorContains(t, d.collectLogs(t.Context()), "4194304-byte limit")
	require.ErrorContains(t, d.Close(), "evidence may be incomplete")
	events := readAuthDiagnosticEvents(t, path)
	require.Len(t, events, 1)
	require.Equal(t, "apiserver-log-collection", events[0].Source)
	require.Contains(t, events[0].Error, "evidence may be incomplete")
}
