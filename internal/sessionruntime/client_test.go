package sessionruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayagent"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
)

const sessionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const gatewayID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
const targetID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

func newRuntime(t *testing.T, ready bool) (*Client, *fake.Clientset) {
	t.Helper()
	kube := fake.NewSimpleClientset()
	port := int32(31000)
	kube.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		object := action.(ktesting.CreateAction).GetObject()
		metadata, err := meta.Accessor(object)
		if err != nil {
			return true, nil, err
		}
		metadata.SetUID(types.UID("uid-" + action.GetResource().Resource + "-" + metadata.GetName()))
		switch value := object.(type) {
		case *corev1.Pod:
			if ready {
				value.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}
			}
		case *corev1.Service:
			value.Spec.Ports[0].NodePort = port
			port++
			slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: value.Name, Namespace: action.GetNamespace(), Labels: map[string]string{discoveryv1.LabelServiceName: value.Name},
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", UID: value.UID}}}, AddressType: discoveryv1.AddressTypeIPv4,
				Ports:     []discoveryv1.EndpointPort{{Port: ptr(int32(gatewayagent.SessionListenerPort)), Protocol: ptr(corev1.ProtocolTCP)}},
				Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"127.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: ptr(true)}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: value.Name, UID: types.UID("uid-pods-" + value.Name)}}}}
			if err := kube.Tracker().Create(discoveryv1.SchemeGroupVersion.WithResource("endpointslices"), slice, action.GetNamespace()); err != nil {
				return true, nil, err
			}
		}
		return false, nil, nil
	})
	credentials, _ := gatewayauth.NewSessionCredentials(make([]byte, 32))
	c, err := NewClient(kube, Options{Namespace: "access-gateway", Image: "registry.test/agent@sha256:" + strings.Repeat("a", 64), NodeName: "worker-1", PublicAddress: "sessions.example.com", ControlPlaneURL: "https://control.example.com", StartupTimeout: time.Second, PollInterval: time.Millisecond, Credentials: credentials})
	if err != nil {
		t.Fatal(err)
	}
	c.callAgent = func(_ context.Context, _ *corev1.Pod, cfg gatewayagent.SessionConfig, path string, result any) error {
		if path == "/stop" {
			*result.(*gateway.CloseSessionResponse) = gateway.CloseSessionResponse{SessionID: cfg.Request.SessionID, Status: "closed"}
		} else {
			*result.(*gateway.CreateSessionResponse) = gateway.CreateSessionResponse{SessionID: cfg.Request.SessionID, Status: "running", ConnectionMode: "native", ListenerPort: gatewayagent.SessionListenerPort, StartedAt: cfg.StartedAt, ExpiresAt: cfg.ExpiresAt}
		}
		return nil
	}
	return c, kube
}

func requestFor(session string) gateway.CreateSessionRequest {
	return gateway.CreateSessionRequest{SessionID: session, TargetID: targetID, TargetPort: 3306, SourceIP: "192.0.2.1", TargetAccount: "readonly", ConnectionMode: "native", TTLSeconds: 600, MaxConnections: gateway.MaxSessionConnections}
}

func TestSessionRuntimeCreatesOneIsolatedPodAndPortPerSession(t *testing.T) {
	c, kube := newRuntime(t, true)
	ctx := context.Background()
	request := requestFor(sessionID)
	first, err := c.CreateApprovedSession(ctx, gatewayID, request, "db.internal")
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.CreateApprovedSession(ctx, gatewayID, request, "db.internal")
	if err != nil || first != again {
		t.Fatalf("replay: %+v %v", again, err)
	}
	second, err := c.CreateApprovedSession(ctx, gatewayID, requestFor("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"), "db.internal")
	if err != nil || second.ExternalPort == first.ExternalPort || second.ListenerPort != first.ListenerPort {
		t.Fatalf("second isolated session: %+v %v", second, err)
	}
	pods, _ := kube.CoreV1().Pods(c.options.Namespace).List(ctx, metav1.ListOptions{})
	if len(pods.Items) != 2 {
		t.Fatalf("created %d Pods", len(pods.Items))
	}
	pod := pods.Items[0]
	if pod.Spec.RestartPolicy != corev1.RestartPolicyNever || pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken || pod.Spec.ActiveDeadlineSeconds == nil || len(pod.Spec.Containers) != 1 {
		t.Fatalf("unsafe agent Pod: %+v", pod.Spec)
	}
	if len(pod.Spec.InitContainers) != 1 {
		t.Fatal("session preparation container is missing")
	}
	for _, container := range []corev1.Container{pod.Spec.InitContainers[0], pod.Spec.Containers[0]} {
		if container.Image != c.options.Image || strings.Join(container.Command, " ") != "/usr/local/bin/gateway-agent" {
			t.Fatal("session containers must select the agent entrypoint in the shared application image")
		}
	}
	encoded, _ := json.Marshal(pod)
	if strings.Contains(string(encoded), "db.internal") || strings.Contains(string(encoded), request.SourceIP) || strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("session secrets leaked into Pod spec")
	}
	if first.ExposureMode != "kubernetes_nodeport" || first.ProcessID != "pod:access-gateway:"+resourceName(sessionID) {
		t.Fatalf("invalid response: %+v", first)
	}
	if _, err := c.CreateApprovedSession(ctx, gatewayID, request, "different.internal"); err == nil {
		t.Fatal("changed target accepted for same session")
	}
	secret, _ := kube.CoreV1().Secrets(c.options.Namespace).Get(ctx, resourceName(sessionID), metav1.GetOptions{})
	cfg, err := gatewayagent.DecodeSessionConfig(secret.Data["session.json"])
	if err != nil || !c.options.Credentials.Verify(gatewayID, sessionID, cfg.AuditToken, time.Now()) || c.options.Credentials.Verify(gatewayID, second.SessionID, cfg.AuditToken, time.Now()) {
		t.Fatal("invalid scoped audit grant")
	}
	if _, err := c.CloseSession(ctx, "", sessionID, "close"); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"pods", "services", "secrets"} {
		_, err := kube.Tracker().Get(corev1.SchemeGroupVersion.WithResource(kind), c.options.Namespace, resourceName(sessionID))
		if !apierrors.IsNotFound(err) {
			t.Fatalf("%s not deleted: %v", kind, err)
		}
	}
	if _, err := c.CloseSession(ctx, "", sessionID, "close-again"); err != nil {
		t.Fatal(err)
	}
	if status, err := c.GetSession(ctx, "", sessionID); err != nil || status.Status != "closed" {
		t.Fatalf("closed status: %+v %v", status, err)
	}
	if _, err := c.CreateApprovedSession(ctx, gatewayID, request, "db.internal"); err == nil {
		t.Fatal("closed session was recreated")
	}
	if _, err := kube.CoreV1().Pods(c.options.Namespace).Get(ctx, resourceName(second.SessionID), metav1.GetOptions{}); err != nil {
		t.Fatalf("another session was removed: %v", err)
	}
}

func TestSessionRuntimeDoesNotExposeUnreadyAgentAndRecoversOrphan(t *testing.T) {
	c, kube := newRuntime(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := c.CreateApprovedSession(ctx, gatewayID, requestFor(sessionID), "db.internal"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unready agent: %v", err)
	}
	services, _ := kube.CoreV1().Services(c.options.Namespace).List(context.Background(), metav1.ListOptions{})
	if len(services.Items) != 0 {
		t.Fatal("unready session received a public port")
	}
	record, _ := kube.CoreV1().ConfigMaps(c.options.Namespace).Get(context.Background(), resourceName(sessionID), metav1.GetOptions{})
	record.Data["expires_at"] = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
	if _, err := kube.CoreV1().ConfigMaps(c.options.Namespace).Update(context.Background(), record, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	// A fresh controller has no in-memory knowledge of the interrupted attempt.
	restarted, err := NewClient(kube, c.options)
	if err != nil {
		t.Fatal(err)
	}
	ended, err := restarted.Reconcile(context.Background())
	if err != nil || len(ended) != 1 || ended[0] != sessionID {
		t.Fatalf("reconcile: %v %v", ended, err)
	}
	if _, err := kube.CoreV1().Pods(c.options.Namespace).Get(context.Background(), record.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("expired Pod remains")
	}
}

func TestSessionRuntimeCloseFencesCreationAndRejectsForeignResources(t *testing.T) {
	c, kube := newRuntime(t, true)
	ctx := context.Background()
	if _, err := c.CloseSession(ctx, "", sessionID, "cancel-before-create"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateApprovedSession(ctx, gatewayID, requestFor(sessionID), "db.internal"); err == nil {
		t.Fatal("pre-cancelled session created")
	}
	other := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"
	if _, err := c.CreateApprovedSession(ctx, gatewayID, requestFor(other), "db.internal"); err != nil {
		t.Fatal(err)
	}
	service, _ := kube.CoreV1().Services(c.options.Namespace).Get(ctx, resourceName(other), metav1.GetOptions{})
	service.OwnerReferences = nil
	if _, err := kube.CoreV1().Services(c.options.Namespace).Update(ctx, service, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CloseSession(ctx, "", other, "close"); err == nil {
		t.Fatal("foreign Service deleted")
	}
}

func TestSessionRuntimeFailedAuditFlushKeepsRevocationRetryable(t *testing.T) {
	c, kube := newRuntime(t, true)
	ctx := context.Background()
	if _, err := c.CreateApprovedSession(ctx, gatewayID, requestFor(sessionID), "db.internal"); err != nil {
		t.Fatal(err)
	}
	c.callAgent = func(context.Context, *corev1.Pod, gatewayagent.SessionConfig, string, any) error {
		return fmt.Errorf("audit unavailable")
	}
	if _, err := c.CloseSession(ctx, "", sessionID, "close"); err == nil {
		t.Fatal("failed stop was reported as closed")
	}
	if err := c.AcknowledgeClosure(ctx, sessionID); err == nil {
		t.Fatal("pending resources were acknowledged as cleaned up")
	}
	if _, err := kube.CoreV1().Pods(c.options.Namespace).Get(ctx, resourceName(sessionID), metav1.GetOptions{}); err != nil {
		t.Fatal("Pod with pending audit was deleted")
	}
	if _, err := kube.CoreV1().Services(c.options.Namespace).Get(ctx, resourceName(sessionID), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("public entry remained open")
	}
	if _, err := c.CreateApprovedSession(ctx, gatewayID, requestFor(sessionID), "db.internal"); err == nil {
		t.Fatal("failed revocation allowed session creation")
	}
}

func TestSessionRuntimeAcknowledgedTombstonesDoNotRepeatCleanup(t *testing.T) {
	c, kube := newRuntime(t, true)
	ctx := context.Background()
	if _, err := c.CloseSession(ctx, "", sessionID, "close"); err != nil {
		t.Fatal(err)
	}
	record, _ := kube.CoreV1().ConfigMaps(c.options.Namespace).Get(ctx, resourceName(sessionID), metav1.GetOptions{})
	record.Data["closed_at"] = time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	if _, err := kube.CoreV1().ConfigMaps(c.options.Namespace).Update(ctx, record, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.AcknowledgeClosure(ctx, sessionID); err != nil {
		t.Fatal(err)
	}
	kube.ClearActions()
	ended, err := c.Reconcile(ctx)
	if err != nil || len(ended) != 0 {
		t.Fatalf("acknowledged record reconciled again: %v %v", ended, err)
	}
	for _, action := range kube.Actions() {
		if !action.Matches("list", "configmaps") {
			t.Fatalf("unexpected repeated cleanup: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
}

func TestSessionRuntimeDoesNotReplaceADeletedAgent(t *testing.T) {
	c, kube := newRuntime(t, true)
	ctx := context.Background()
	if _, err := c.CreateApprovedSession(ctx, gatewayID, requestFor(sessionID), "db.internal"); err != nil {
		t.Fatal(err)
	}
	if err := kube.CoreV1().Pods(c.options.Namespace).Delete(ctx, resourceName(sessionID), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateApprovedSession(ctx, gatewayID, requestFor(sessionID), "db.internal"); err == nil {
		t.Fatal("session agent was recreated after deletion")
	}
	if _, err := kube.CoreV1().Pods(c.options.Namespace).Get(ctx, resourceName(sessionID), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("replacement Pod remains")
	}
}
