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
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/onsi/ginkgo/v2"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"

	"sigs.k8s.io/controller-runtime/pkg/client"

	hypershiftv1beta1 "github.com/openshift/hypershift/api/hypershift/v1beta1"

	hcpdiscovery "github.com/Azure/ARO-HCP/tooling/hcpctl/pkg/hcp"
)

const (
	adminAuthDiagnosticKubeconfig = "ARO_HCP_AUTH_DIAGNOSTICS_KUBECONFIG"
	adminAuthDiagnosticInterval   = 2 * time.Second
	adminAuthDiagnosticDuration   = 3 * time.Minute
	adminAuthDiagnosticRequest    = 5 * time.Second
	adminAuthDiagnosticLogLimit   = 4 << 20
)

type authCertificate struct {
	SHA256         string `json:"sha256"`
	Subject        string `json:"subject"`
	Issuer         string `json:"issuer"`
	SerialNumber   string `json:"serial_number"`
	SubjectKeyID   string `json:"subject_key_id,omitempty"`
	AuthorityKeyID string `json:"authority_key_id,omitempty"`
}

type authDiagnosticEvent struct {
	ObservedAt      time.Time         `json:"observed_at"`
	Source          string            `json:"source"`
	Namespace       string            `json:"namespace,omitempty"`
	Pod             string            `json:"pod,omitempty"`
	Node            string            `json:"node,omitempty"`
	ResourceVersion string            `json:"resource_version,omitempty"`
	BundleSHA256    string            `json:"bundle_sha256,omitempty"`
	Certificates    []authCertificate `json:"certificates,omitempty"`
	Images          map[string]string `json:"images,omitempty"`
	HTTPStatus      int               `json:"http_status,omitempty"`
	Log             string            `json:"log,omitempty"`
	Error           string            `json:"error,omitempty"`
}

// AdminCredentialDiagnostics observes client-CA propagation without changing the
// initial viability result. It never writes kubeconfigs, private keys, or PEM data.
type AdminCredentialDiagnostics struct {
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	start     time.Time
	duration  time.Duration
	interval  time.Duration
	logger    logr.Logger
	kube      kubernetes.Interface
	discover  func(context.Context) (string, error)
	readCA    func(context.Context, string, string) ([]byte, error)

	mu        sync.Mutex
	namespace string
	file      *os.File
	encoder   *json.Encoder
	previous  map[string]string
	failures  map[string]error
	writeErr  error
}

// StartAdminCredentialDiagnostics is a no-op unless
// ARO_HCP_AUTH_DIAGNOSTICS_KUBECONFIG names a management-cluster kubeconfig.
// Start it before cluster creation and close it before normal resource cleanup.
func (tc *perItOrDescribeTestContext) StartAdminCredentialDiagnostics(ctx context.Context, managedResourceGroup string) (*AdminCredentialDiagnostics, error) {
	kubeconfig := os.Getenv(adminAuthDiagnosticKubeconfig)
	if kubeconfig == "" {
		return nil, nil
	}
	if tc.LogDirPath == "" {
		return nil, fmt.Errorf("%s requires ARTIFACT_DIR", adminAuthDiagnosticKubeconfig)
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load auth diagnostic management kubeconfig: %w", err)
	}
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		return nil, fmt.Errorf("admin authentication diagnostics require kubectl: %w", err)
	}
	config.Timeout = adminAuthDiagnosticRequest
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create auth diagnostic management client: %w", err)
	}
	hcpScheme := runtime.NewScheme()
	if err := hypershiftv1beta1.AddToScheme(hcpScheme); err != nil {
		return nil, fmt.Errorf("register HostedCluster types: %w", err)
	}
	controlClient, err := client.New(config, client.Options{Scheme: hcpScheme})
	if err != nil {
		return nil, fmt.Errorf("create auth diagnostic HostedCluster client: %w", err)
	}
	subscriptionID, err := tc.SubscriptionID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve auth diagnostic subscription: %w", err)
	}
	discovery := hcpdiscovery.NewDiscovery(controlClient)
	// Validate access before creating the hosted cluster. The target need not exist yet.
	if _, err := discovery.ListAllClusters(ctx); err != nil {
		return nil, fmt.Errorf("validate auth diagnostic HostedCluster access: %w", err)
	}
	directory := filepath.Join(tc.LogDirPath, "admin-auth-diagnostics")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create auth diagnostic directory: %w", err)
	}
	file, err := os.OpenFile(filepath.Join(directory, "observations.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("create auth diagnostic observations: %w", err)
	}
	observeCtx, cancel := context.WithCancel(ctx)
	d := &AdminCredentialDiagnostics{
		ctx: observeCtx, cancel: cancel, done: make(chan struct{}),
		start: time.Now().UTC(), duration: adminAuthDiagnosticDuration,
		interval: adminAuthDiagnosticInterval, logger: ginkgo.GinkgoLogr,
		kube: kube, file: file, encoder: json.NewEncoder(file),
		previous: map[string]string{}, failures: map[string]error{},
	}
	d.discover = func(ctx context.Context) (string, error) {
		clusters, err := discovery.ListAllClusters(ctx)
		if err != nil {
			return "", err
		}
		return authDiagnosticNamespace(clusters, subscriptionID, managedResourceGroup)
	}
	d.readCA = func(ctx context.Context, namespace, pod string) ([]byte, error) {
		return readAuthDiagnosticMountedCA(ctx, kubectl, kubeconfig, namespace, pod)
	}
	go func() {
		defer utilruntime.HandleCrash()
		defer close(d.done)
		d.run()
	}()
	d.logger.Info("Admin authentication diagnostics enabled; normal cleanup remains enabled.", "directory", directory)
	return d, nil
}

func readAuthDiagnosticMountedCA(ctx context.Context, kubectl, kubeconfig, namespace, pod string) ([]byte, error) {
	command := exec.CommandContext(ctx, kubectl, "--kubeconfig", kubeconfig, "--namespace", namespace,
		"exec", pod, "--container", "kube-apiserver", "--", "cat", "/etc/kubernetes/certs/client-ca/ca.crt")
	command.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("read mounted client CA: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func authDiagnosticNamespace(clusters []hcpdiscovery.HCPInfo, subscriptionID, managedResourceGroup string) (string, error) {
	var namespace string
	for _, cluster := range clusters {
		if !strings.EqualFold(cluster.SubscriptionID, subscriptionID) || !strings.EqualFold(cluster.ResourceGroupName, managedResourceGroup) {
			continue
		}
		if namespace != "" {
			return "", fmt.Errorf("multiple HostedClusters match subscription %s and managed resource group %s", subscriptionID, managedResourceGroup)
		}
		namespace = cluster.Namespace
	}
	if namespace == "" {
		return "", fmt.Errorf("HostedCluster for managed resource group %s is not present yet", managedResourceGroup)
	}
	return namespace, nil
}

func (d *AdminCredentialDiagnostics) run() {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		d.sample()
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *AdminCredentialDiagnostics) sample() {
	namespace := d.getNamespace()
	if namespace == "" {
		var err error
		namespace, err = d.discover(d.ctx)
		d.record(authDiagnosticEvent{Source: "namespace", Namespace: namespace}, err)
		if err != nil {
			return
		}
		d.mu.Lock()
		d.namespace = namespace
		d.mu.Unlock()
	}
	cm, err := d.kube.CoreV1().ConfigMaps(namespace).Get(d.ctx, "client-ca", metav1.GetOptions{})
	event := authDiagnosticEvent{Source: "configmap", Namespace: namespace}
	if err == nil {
		event.ResourceVersion = cm.ResourceVersion
		event.BundleSHA256, event.Certificates, err = authDiagnosticCertificates([]byte(cm.Data["ca.crt"]))
	}
	d.record(event, err)
	pods, err := d.kube.CoreV1().Pods(namespace).List(d.ctx, metav1.ListOptions{LabelSelector: "app=kube-apiserver"})
	if err == nil && len(pods.Items) == 0 {
		err = errors.New("no kube-apiserver pods are present yet")
	}
	d.record(authDiagnosticEvent{Source: "pods", Namespace: namespace}, err)
	if err != nil {
		return
	}
	for _, pod := range pods.Items {
		if d.ctx.Err() != nil {
			return
		}
		event := authDiagnosticEvent{Source: "mounted-ca", Namespace: namespace, Pod: pod.Name, Node: pod.Spec.NodeName, Images: map[string]string{}}
		for _, container := range pod.Status.ContainerStatuses {
			event.Images[container.Name] = container.ImageID
		}
		readCtx, cancel := context.WithTimeout(d.ctx, adminAuthDiagnosticRequest)
		bundle, err := d.readCA(readCtx, namespace, pod.Name)
		cancel()
		if err == nil {
			event.BundleSHA256, event.Certificates, err = authDiagnosticCertificates(bundle)
		}
		d.record(event, err)
	}
}

func authDiagnosticCertificates(data []byte) (string, []authCertificate, error) {
	sum := sha256.Sum256(data)
	certificates, err := certutil.ParseCertsPEM(data)
	if err != nil {
		return hex.EncodeToString(sum[:]), nil, err
	}
	result := make([]authCertificate, 0, len(certificates))
	for _, certificate := range certificates {
		fingerprint := sha256.Sum256(certificate.Raw)
		result = append(result, authCertificate{
			SHA256: hex.EncodeToString(fingerprint[:]), Subject: certificate.Subject.String(),
			Issuer: certificate.Issuer.String(), SerialNumber: certificate.SerialNumber.String(),
			SubjectKeyID: hex.EncodeToString(certificate.SubjectKeyId), AuthorityKeyID: hex.EncodeToString(certificate.AuthorityKeyId),
		})
	}
	return hex.EncodeToString(sum[:]), result, nil
}

func (d *AdminCredentialDiagnostics) getNamespace() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.namespace
}

func (d *AdminCredentialDiagnostics) record(event authDiagnosticEvent, err error) {
	if d.ctx.Err() != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	key := event.Source + "/" + event.Pod
	if err != nil {
		event.Error = err.Error()
		if event.Source != "guest-probe" {
			d.failures[key] = err
		}
	} else {
		delete(d.failures, key)
	}
	state, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		d.writeErr = marshalErr
		d.logger.Error(marshalErr, "Failed to encode auth diagnostic observation.")
		d.cancel()
		return
	}
	if d.previous[key] != string(state) && event.Source != "apiserver-log" {
		d.logger.Info("Admin authentication diagnostic state changed.", "source", event.Source, "pod", event.Pod, "bundleSHA256", event.BundleSHA256, "httpStatus", event.HTTPStatus, "error", event.Error)
		d.previous[key] = string(state)
	}
	event.ObservedAt = time.Now().UTC()
	if err := d.encoder.Encode(event); err != nil {
		d.writeErr = err
		d.logger.Error(err, "Failed to write auth diagnostic observation.")
		d.cancel()
	}
}

// Finish probes the unchanged customer credential for three minutes, captures
// relevant API-server logs, and preserves initialErr even if authentication recovers.
// A nil receiver returns initialErr unchanged, keeping the default test behavior.
func (d *AdminCredentialDiagnostics) Finish(ctx context.Context, config *rest.Config, initialErr error) error {
	if d == nil {
		return initialErr
	}
	probeErr := d.probeCredential(ctx, config)
	logErr := d.collectLogs(ctx)
	return errors.Join(initialErr, probeErr, logErr, d.Close())
}

func (d *AdminCredentialDiagnostics) probeCredential(ctx context.Context, config *rest.Config) error {
	event := authDiagnosticEvent{Source: "credential"}
	var err error
	_, event.Certificates, err = authDiagnosticCertificates(config.CertData)
	d.record(event, err)
	if err != nil {
		return fmt.Errorf("inspect issued customer certificate: %w", err)
	}
	probeConfig := rest.CopyConfig(config)
	probeConfig.Timeout = adminAuthDiagnosticRequest
	kube, err := kubernetes.NewForConfig(probeConfig)
	if err != nil {
		return fmt.Errorf("create same-credential probe client: %w", err)
	}
	probeCtx, cancel := context.WithTimeout(ctx, d.duration)
	defer cancel()
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		_, err := kube.CoreV1().Services("default").List(probeCtx, metav1.ListOptions{Limit: 1})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if probeCtx.Err() != nil {
			return nil
		}
		event := authDiagnosticEvent{Source: "guest-probe", HTTPStatus: 200}
		if err != nil {
			event.HTTPStatus = 0
			var status apierrors.APIStatus
			if errors.As(err, &status) {
				event.HTTPStatus = int(status.Status().Code)
			}
		}
		d.record(event, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.ctx.Done():
			return d.ctx.Err()
		case <-probeCtx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (d *AdminCredentialDiagnostics) collectLogs(ctx context.Context) error {
	namespace := d.getNamespace()
	if namespace == "" {
		return errors.New("cannot collect API-server logs: control-plane namespace was not discovered")
	}
	listCtx, cancel := context.WithTimeout(ctx, adminAuthDiagnosticRequest)
	pods, err := d.kube.CoreV1().Pods(namespace).List(listCtx, metav1.ListOptions{LabelSelector: "app=kube-apiserver"})
	cancel()
	if err != nil {
		return fmt.Errorf("list API servers for authentication logs: %w", err)
	}
	if len(pods.Items) == 0 {
		return errors.New("cannot collect authentication logs: no kube-apiserver pods were found")
	}
	var errs []error
	for _, pod := range pods.Items {
		logCtx, cancel := context.WithTimeout(ctx, adminAuthDiagnosticRequest)
		limit := int64(adminAuthDiagnosticLogLimit)
		data, err := d.kube.CoreV1().Pods(namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
			Container: "kube-apiserver", SinceTime: &metav1.Time{Time: d.start},
			Timestamps: true, LimitBytes: &limit,
		}).DoRaw(logCtx)
		cancel()
		if err == nil && len(data) >= adminAuthDiagnosticLogLimit {
			err = fmt.Errorf("API-server logs reached the %d-byte limit; evidence may be incomplete", adminAuthDiagnosticLogLimit)
		}
		d.record(authDiagnosticEvent{Source: "apiserver-log-collection", Namespace: namespace, Pod: pod.Name}, err)
		if err != nil {
			errs = append(errs, fmt.Errorf("collect logs for %s: %w", pod.Name, err))
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 4096), adminAuthDiagnosticLogLimit)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Unable to authenticate") || strings.Contains(line, "Loaded a new CA Bundle") ||
				strings.Contains(line, "Loaded client CA") || strings.Contains(line, "customer-system-admin-signer") {
				d.record(authDiagnosticEvent{Source: "apiserver-log", Namespace: namespace, Pod: pod.Name, Log: line}, nil)
			}
		}
		if err := scanner.Err(); err != nil {
			errs = append(errs, fmt.Errorf("parse logs for %s: %w", pod.Name, err))
		}
	}
	return errors.Join(errs...)
}

// Close stops the observer before teardown and reports incomplete collection.
func (d *AdminCredentialDiagnostics) Close() error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		d.cancel()
		<-d.done
		d.mu.Lock()
		defer d.mu.Unlock()
		var errs []error
		for source, err := range d.failures {
			errs = append(errs, fmt.Errorf("auth diagnostics %s: %w", source, err))
		}
		d.closeErr = errors.Join(append(errs, d.writeErr, d.file.Close())...)
	})
	return d.closeErr
}
