package sessionruntime

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/retry"

	"github.com/srex-run/access-gateway/internal/gatewayagent"
)

func (c *Client) ensurePod(ctx context.Context, record *corev1.ConfigMap) error {
	if err := c.requireActive(ctx, record); err != nil {
		return err
	}
	pods := c.kube.CoreV1().Pods(c.options.Namespace)
	pod, err := pods.Get(ctx, record.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		current, getErr := c.kube.CoreV1().ConfigMaps(c.options.Namespace).Get(ctx, record.Name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("check session Pod identity: %w", getErr)
		}
		if current.UID != record.UID || current.Data["state"] != "active" || current.Data["pod_uid"] != "" {
			return fmt.Errorf("session agent was already created or revoked")
		}
		started, _ := time.Parse(time.RFC3339Nano, record.Data["started_at"])
		expires, _ := time.Parse(time.RFC3339Nano, record.Data["expires_at"])
		security := &corev1.SecurityContext{AllowPrivilegeEscalation: ptr(false), ReadOnlyRootFilesystem: ptr(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}
		pod, err = pods.Create(ctx, &corev1.Pod{ObjectMeta: resourceMeta(record), Spec: corev1.PodSpec{
			Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{c.options.NodeName}}}}},
			}}},
			RestartPolicy: corev1.RestartPolicyNever, AutomountServiceAccountToken: ptr(false),
			TerminationGracePeriodSeconds: ptr(int64(30)), ActiveDeadlineSeconds: ptr(int64(expires.Sub(started).Seconds()) + 600),
			SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr(true), RunAsUser: ptr(int64(65532)), RunAsGroup: ptr(int64(65532)), FSGroup: ptr(int64(65532)), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
			InitContainers: []corev1.Container{{Name: "prepare-session", Image: c.options.Image, Command: []string{"/usr/local/bin/gateway-agent"}, Args: []string{"prepare-session"}, SecurityContext: security,
				Resources:    corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("32Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}},
				VolumeMounts: []corev1.VolumeMount{{Name: "grant", MountPath: "/source/session", ReadOnly: true}, {Name: "runtime", MountPath: "/run/session"}}}},
			Containers: []corev1.Container{{Name: "agent", Image: c.options.Image, Command: []string{"/usr/local/bin/gateway-agent"}, Args: []string{"session"}, SecurityContext: security,
				Ports:          []corev1.ContainerPort{{Name: "tcp", ContainerPort: gatewayagent.SessionListenerPort}, {Name: "management", ContainerPort: gatewayagent.SessionManagementPort}, {Name: "health", ContainerPort: gatewayagent.SessionHealthPort}},
				ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt(gatewayagent.SessionHealthPort)}}, PeriodSeconds: 1, TimeoutSeconds: 1},
				Resources:      corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("64Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("512Mi")}},
				VolumeMounts:   []corev1.VolumeMount{{Name: "runtime", MountPath: "/run/session"}, {Name: "terminal", MountPath: "/tmp"}}}},
			Volumes: []corev1.Volume{{Name: "grant", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: record.Name, DefaultMode: ptr(int32(0440))}}},
				{Name: "terminal", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: ptr(resource.MustParse("32Mi"))}}},
				{Name: "runtime", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: ptr(resource.MustParse("16Mi"))}}}},
		}}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			pod, err = pods.Get(ctx, record.Name, metav1.GetOptions{})
		}
	}
	if err != nil {
		return fmt.Errorf("create session Pod: %w", err)
	}
	if !owned(pod.ObjectMeta, record) || pod.Spec.RestartPolicy != corev1.RestartPolicyNever || pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken ||
		len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Image != c.options.Image || !reflect.DeepEqual(pod.Spec.Containers[0].Command, []string{"/usr/local/bin/gateway-agent"}) || !reflect.DeepEqual(pod.Spec.Containers[0].Args, []string{"session"}) ||
		len(pod.Spec.InitContainers) != 1 || pod.Spec.InitContainers[0].Image != c.options.Image || !reflect.DeepEqual(pod.Spec.InitContainers[0].Command, []string{"/usr/local/bin/gateway-agent"}) || !reflect.DeepEqual(pod.Spec.InitContainers[0].Args, []string{"prepare-session"}) {
		return fmt.Errorf("session Pod does not match the managed workload")
	}
	return c.bindPodIdentity(ctx, record, pod)
}

func (c *Client) bindPodIdentity(ctx context.Context, record *corev1.ConfigMap, pod *corev1.Pod) error {
	if pod.UID == "" {
		return fmt.Errorf("session Pod identity is missing")
	}
	records := c.kube.CoreV1().ConfigMaps(c.options.Namespace)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := records.Get(ctx, record.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if current.UID != record.UID || current.Data["state"] != "active" {
			return fmt.Errorf("session was revoked during Pod creation")
		}
		if previous := current.Data["pod_uid"]; previous != "" {
			if previous != string(pod.UID) {
				return fmt.Errorf("session agent identity changed")
			}
			return nil
		}
		current.Data["pod_uid"] = string(pod.UID)
		_, err = records.Update(ctx, current, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return fmt.Errorf("persist session Pod identity: %w", err)
	}
	return nil
}

func (c *Client) ensureService(ctx context.Context, record *corev1.ConfigMap) (*corev1.Service, error) {
	if err := c.requireActive(ctx, record); err != nil {
		return nil, err
	}
	services := c.kube.CoreV1().Services(c.options.Namespace)
	service, err := services.Get(ctx, record.Name, metav1.GetOptions{})
	selector := labels(record.Labels[sessionLabel])
	if apierrors.IsNotFound(err) {
		service, err = services.Create(ctx, &corev1.Service{ObjectMeta: resourceMeta(record), Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort, ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			Selector: selector, Ports: []corev1.ServicePort{{Name: "tcp", Protocol: corev1.ProtocolTCP, Port: gatewayagent.SessionListenerPort, TargetPort: intstr.FromInt(gatewayagent.SessionListenerPort)}},
		}}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			service, err = services.Get(ctx, record.Name, metav1.GetOptions{})
		}
	}
	if err != nil {
		return nil, fmt.Errorf("create session NodePort Service: %w", err)
	}
	if !owned(service.ObjectMeta, record) || service.Spec.Type != corev1.ServiceTypeNodePort || service.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal ||
		!reflect.DeepEqual(service.Spec.Selector, selector) || len(service.Spec.Ports) != 1 || service.Spec.PublishNotReadyAddresses ||
		service.Spec.Ports[0].Port != gatewayagent.SessionListenerPort || service.Spec.Ports[0].TargetPort != intstr.FromInt(gatewayagent.SessionListenerPort) ||
		service.Spec.Ports[0].Protocol != corev1.ProtocolTCP || service.Spec.Ports[0].NodePort < 1 {
		return nil, fmt.Errorf("session Service does not match the managed exposure")
	}
	return service, nil
}

func (c *Client) endpointsReady(ctx context.Context, service *corev1.Service, pod *corev1.Pod) (bool, error) {
	slices, err := c.kube.DiscoveryV1().EndpointSlices(c.options.Namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + service.Name})
	if err != nil {
		return false, fmt.Errorf("get session Service endpoints: %w", err)
	}
	for _, slice := range slices.Items {
		serviceOwned := false
		for _, owner := range slice.OwnerReferences {
			if owner.Kind == "Service" && owner.UID == service.UID {
				serviceOwned = true
			}
		}
		if !serviceOwned {
			continue
		}
		portReady := false
		for _, port := range slice.Ports {
			if port.Port != nil && *port.Port == gatewayagent.SessionListenerPort && port.Protocol != nil && *port.Protocol == corev1.ProtocolTCP {
				portReady = true
			}
		}
		if !portReady {
			continue
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.TargetRef != nil && endpoint.TargetRef.Kind == "Pod" && endpoint.TargetRef.Name == pod.Name && endpoint.TargetRef.UID == pod.UID &&
				endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready && (endpoint.Conditions.Terminating == nil || !*endpoint.Conditions.Terminating) {
				for _, address := range endpoint.Addresses {
					if net.ParseIP(address).Equal(net.ParseIP(pod.Status.PodIP)) {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}
