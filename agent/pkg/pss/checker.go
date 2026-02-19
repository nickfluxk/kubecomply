// Package pss evaluates pods and workloads against the Kubernetes Pod Security
// Standards (PSS) Baseline and Restricted profiles.
package pss

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/kubecomply/kubecomply/pkg/k8s"
	"github.com/kubecomply/kubecomply/pkg/scanner"
)

// Profile represents a Pod Security Standards profile level.
type Profile string

const (
	ProfileBaseline   Profile = "baseline"
	ProfileRestricted Profile = "restricted"
)

// Checker evaluates pods and workloads against Pod Security Standards.
// It implements the scanner.Analyzer interface.
type Checker struct {
	client *k8s.Client
	logger *slog.Logger
}

// Name returns the analyzer name.
func (c *Checker) Name() string { return "pss" }

// Analyze implements scanner.Analyzer by delegating to Check.
func (c *Checker) Analyze(ctx context.Context, namespaces []string) ([]scanner.Finding, error) {
	return c.Check(ctx, namespaces)
}

// NewChecker creates a new PSS checker.
func NewChecker(client *k8s.Client, logger *slog.Logger) *Checker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Checker{
		client: client,
		logger: logger,
	}
}

// Check evaluates all pods and workloads in the given namespaces against
// PSS Baseline and Restricted profiles.
func (c *Checker) Check(ctx context.Context, namespaces []string) ([]scanner.Finding, error) {
	c.logger.Info("starting Pod Security Standards check")

	now := time.Now()
	var findings []scanner.Finding

	for _, ns := range namespaces {
		// Check pods directly.
		pods, err := c.client.ListPods(ctx, ns)
		if err != nil {
			c.logger.Warn("failed to list pods", "namespace", ns, "error", err)
			continue
		}
		for i := range pods {
			resource := fmt.Sprintf("Pod/%s/%s", pods[i].Namespace, pods[i].Name)
			findings = append(findings, c.checkPodSpec(&pods[i].Spec, resource, pods[i].Namespace, now)...)
		}

		// Check deployments.
		deployments, err := c.client.ListDeployments(ctx, ns)
		if err != nil {
			c.logger.Warn("failed to list deployments", "namespace", ns, "error", err)
			continue
		}
		for i := range deployments {
			resource := fmt.Sprintf("Deployment/%s/%s", deployments[i].Namespace, deployments[i].Name)
			findings = append(findings, c.checkPodSpec(&deployments[i].Spec.Template.Spec, resource, deployments[i].Namespace, now)...)
		}

		// Check daemonsets.
		daemonsets, err := c.client.ListDaemonSets(ctx, ns)
		if err != nil {
			c.logger.Warn("failed to list daemonsets", "namespace", ns, "error", err)
			continue
		}
		for i := range daemonsets {
			resource := fmt.Sprintf("DaemonSet/%s/%s", daemonsets[i].Namespace, daemonsets[i].Name)
			findings = append(findings, c.checkPodSpec(&daemonsets[i].Spec.Template.Spec, resource, daemonsets[i].Namespace, now)...)
		}

		// Check statefulsets.
		statefulsets, err := c.client.ListStatefulSets(ctx, ns)
		if err != nil {
			c.logger.Warn("failed to list statefulsets", "namespace", ns, "error", err)
			continue
		}
		for i := range statefulsets {
			resource := fmt.Sprintf("StatefulSet/%s/%s", statefulsets[i].Namespace, statefulsets[i].Name)
			findings = append(findings, c.checkPodSpec(&statefulsets[i].Spec.Template.Spec, resource, statefulsets[i].Namespace, now)...)
		}
	}

	c.logger.Info("PSS check complete", "findings", len(findings))
	return findings, nil
}

// checkPodSpec evaluates a single PodSpec against PSS checks.
func (c *Checker) checkPodSpec(spec *corev1.PodSpec, resource, namespace string, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	// PSS Baseline checks.
	findings = append(findings, c.checkPrivileged(spec, resource, namespace, now)...)
	findings = append(findings, c.checkHostNamespaces(spec, resource, namespace, now)...)
	findings = append(findings, c.checkHostPorts(spec, resource, namespace, now)...)
	findings = append(findings, c.checkCapabilities(spec, resource, namespace, now)...)
	findings = append(findings, c.checkVolumeTypes(spec, resource, namespace, now)...)
	findings = append(findings, c.checkProcMount(spec, resource, namespace, now)...)

	// PSS Restricted checks.
	findings = append(findings, c.checkRunAsNonRoot(spec, resource, namespace, now)...)
	findings = append(findings, c.checkSeccompProfile(spec, resource, namespace, now)...)
	findings = append(findings, c.checkDropAllCapabilities(spec, resource, namespace, now)...)
	findings = append(findings, c.checkAllowPrivilegeEscalation(spec, resource, namespace, now)...)
	findings = append(findings, c.checkReadOnlyRootFilesystem(spec, resource, namespace, now)...)

	return findings
}

// allContainers returns all containers in a pod spec (init + regular + ephemeral).
func allContainers(spec *corev1.PodSpec) []corev1.Container {
	var containers []corev1.Container
	containers = append(containers, spec.InitContainers...)
	containers = append(containers, spec.Containers...)
	for _, ec := range spec.EphemeralContainers {
		containers = append(containers, corev1.Container{
			Name:            ec.Name,
			Image:           ec.Image,
			SecurityContext: ec.SecurityContext,
			Ports:           ec.Ports,
			VolumeMounts:    ec.VolumeMounts,
		})
	}
	return containers
}

// --- Baseline Checks ---

// checkPrivileged verifies no containers run in privileged mode.
func (c *Checker) checkPrivileged(spec *corev1.PodSpec, resource, namespace string, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	for _, container := range allContainers(spec) {
		if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			findings = append(findings, scanner.Finding{
				ID:          "PSS-B001",
				Title:       "Privileged container",
				Description: fmt.Sprintf("Container %q in %s runs in privileged mode", container.Name, resource),
				Severity:    scanner.SeverityCritical,
				Status:      scanner.StatusFail,
				Category:    "pss",
				Resource:    resource,
				Namespace:   namespace,
				Remediation: "Set securityContext.privileged to false. Privileged containers have full access to the host.",
				Details: map[string]string{
					"container": container.Name,
					"profile":   string(ProfileBaseline),
				},
				Timestamp: now,
			})
		}
	}

	return findings
}

// checkHostNamespaces verifies pods don't share host namespaces.
func (c *Checker) checkHostNamespaces(spec *corev1.PodSpec, resource, namespace string, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	if spec.HostNetwork {
		findings = append(findings, scanner.Finding{
			ID:          "PSS-B002",
			Title:       "hostNetwork enabled",
			Description: fmt.Sprintf("%s uses hostNetwork, sharing the host's network namespace", resource),
			Severity:    scanner.SeverityHigh,
			Status:      scanner.StatusFail,
			Category:    "pss",
			Resource:    resource,
			Namespace:   namespace,
			Remediation: "Set spec.hostNetwork to false unless the pod genuinely requires host network access.",
			Details:     map[string]string{"profile": string(ProfileBaseline)},
			Timestamp:   now,
		})
	}

	if spec.HostPID {
		findings = append(findings, scanner.Finding{
			ID:          "PSS-B003",
			Title:       "hostPID enabled",
			Description: fmt.Sprintf("%s uses hostPID, sharing the host's PID namespace", resource),
			Severity:    scanner.SeverityHigh,
			Status:      scanner.StatusFail,
			Category:    "pss",
			Resource:    resource,
			Namespace:   namespace,
			Remediation: "Set spec.hostPID to false. Sharing the host PID namespace allows containers to see and signal host processes.",
			Details:     map[string]string{"profile": string(ProfileBaseline)},
			Timestamp:   now,
		})
	}

	if spec.HostIPC {
		findings = append(findings, scanner.Finding{
			ID:          "PSS-B004",
			Title:       "hostIPC enabled",
			Description: fmt.Sprintf("%s uses hostIPC, sharing the host's IPC namespace", resource),
			Severity:    scanner.SeverityHigh,
			Status:      scanner.StatusFail,
			Category:    "pss",
			Resource:    resource,
			Namespace:   namespace,
			Remediation: "Set spec.hostIPC to false. Sharing the host IPC namespace enables container access to host shared memory.",
			Details:     map[string]string{"profile": string(ProfileBaseline)},
			Timestamp:   now,
		})
	}

	return findings
}

// checkHostPorts checks for containers using host ports.
func (c *Checker) checkHostPorts(spec *corev1.PodSpec, resource, namespace string, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	for _, container := range allContainers(spec) {
		for _, port := range container.Ports {
			if port.HostPort != 0 {
				findings = append(findings, scanner.Finding{
					ID:          "PSS-B005",
					Title:       "Container uses hostPort",
					Description: fmt.Sprintf("Container %q in %s uses hostPort %d", container.Name, resource, port.HostPort),
					Severity:    scanner.SeverityMedium,
					Status:      scanner.StatusFail,
					Category:    "pss",
					Resource:    resource,
					Namespace:   namespace,
					Remediation: "Remove hostPort mapping. Use Services or Ingress to expose ports instead.",
					Details: map[string]string{
						"container": container.Name,
						"host_port": fmt.Sprintf("%d", port.HostPort),
						"profile":   string(ProfileBaseline),
					},
					Timestamp: now,
				})
			}
		}
	}

	return findings
}

// checkCapabilities checks for dangerous added capabilities (Baseline).
func (c *Checker) checkCapabilities(spec *corev1.PodSpec, resource, namespace string, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	// Baseline disallows adding capabilities beyond a safe set.
	safeCapabilities := map[corev1.Capability]bool{
		"AUDIT_WRITE":      true,
		"CHOWN":            true,
		"DAC_OVERRIDE":     true,
		"FOWNER":           true,
		"FSETID":           true,
		"KILL":             true,
		"MKNOD":            true,
		"NET_BIND_SERVICE": true,
		"SETFCAP":          true,
		"SETGID":           true,
		"SETPCAP":          true,
		"SETUID":           true,
		"SYS_CHROOT":       true,
	}

	for _, container := range allContainers(spec) {
		if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
			continue
		}
		for _, cap := range container.SecurityContext.Capabilities.Add {
			if !safeCapabilities[cap] {
				findings = append(findings, scanner.Finding{
					ID:          "PSS-B006",
					Title:       "Dangerous capability added",
					Description: fmt.Sprintf("Container %q in %s adds capability %s which is not in the Baseline safe set", container.Name, resource, cap),
					Severity:    scanner.SeverityHigh,
					Status:      scanner.StatusFail,
					Category:    "pss",
					Resource:    resource,
					Namespace:   namespace,
					Remediation: fmt.Sprintf("Remove capability %s from securityContext.capabilities.add. Only baseline-approved capabilities should be added.", cap),
					Details: map[string]string{
						"container":  container.Name,
						"capability": string(cap),
						"profile":    string(ProfileBaseline),
					},
					Timestamp: now,
				})
			}
		}
	}

	return findings
}

// checkVolumeTypes checks for disallowed volume types.
func (c *Checker) checkVolumeTypes(spec *corev1.PodSpec, resource, namespace string, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	for _, vol := range spec.Volumes {
		if vol.HostPath != nil {
			findings = append(findings, scanner.Finding{
				ID:          "PSS-B007",
				Title:       "HostPath volume mount",
				Description: fmt.Sprintf("%s mounts a hostPath volume %q at %s", resource, vol.Name, vol.HostPath.Path),
				Severity:    scanner.SeverityHigh,
				Status:      scanner.StatusFail,
				Category:    "pss",
				Resource:    resource,
				Namespace:   namespace,
				Remediation: "Replace hostPath volumes with persistent volumes, ConfigMaps, or Secrets.",
				Details: map[string]string{
					"volume_name": vol.Name,
					"host_path":   vol.HostPath.Path,
					"profile":     string(ProfileBaseline),
				},
				Timestamp: now,
			})
		}
	}

	return findings
}

// checkProcMount verifies containers don't set a non-default procMount.
func (c *Checker) checkProcMount(spec *corev1.PodSpec, resource, namespace string, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	for _, container := range allContainers(spec) {
		if container.SecurityContext != nil && container.SecurityContext.ProcMount != nil {
			mount := *container.SecurityContext.ProcMount
			if mount != corev1.DefaultProcMount {
				findings = append(findings, scanner.Finding{
					ID:          "PSS-B008",
					Title:       "Non-default procMount",
					Description: fmt.Sprintf("Container %q in %s uses procMount %q instead of Default", container.Name, resource, mount),
					Severity:    scanner.SeverityMedium,
					Status:      scanner.StatusFail,
					Category:    "pss",
					Resource:    resource,
					Namespace:   namespace,
					Remediation: "Set securityContext.procMount to Default or remove the field.",
					Details: map[string]string{
						"container": container.Name,
						"procMount": string(mount),
						"profile":   string(ProfileBaseline),
					},
					Timestamp: now,
				})
			}
		}
	}

	return findings
}

// --- Restricted Checks ---

// checkRunAsNonRoot verifies pods/containers run as non-root.
func (c *Checker) checkRunAsNonRoot(spec *corev1.PodSpec, resource, namespace string, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	podLevelNonRoot := spec.SecurityContext != nil &&
		spec.SecurityContext.RunAsNonRoot != nil &&
		*spec.SecurityContext.RunAsNonRoot

	for _, container := range allContainers(spec) {
		containerNonRoot := container.SecurityContext != nil &&
			container.SecurityContext.RunAsNonRoot != nil &&
			*container.SecurityContext.RunAsNonRoot

		containerHasUID := container.SecurityContext != nil &&
			container.SecurityContext.RunAsUser != nil &&
			*container.SecurityContext.RunAsUser > 0

		podHasUID := spec.SecurityContext != nil &&
			spec.SecurityContext.RunAsUser != nil &&
			*spec.SecurityContext.RunAsUser > 0

		if !podLevelNonRoot && !containerNonRoot && !containerHasUID && !podHasUID {
			findings = append(findings, scanner.Finding{
				ID:          "PSS-R001",
				Title:       "Container may run as root",
				Description: fmt.Sprintf("Container %q in %s does not set runAsNonRoot: true and does not specify a non-root runAsUser", container.Name, resource),
				Severity:    scanner.SeverityHigh,
				Status:      scanner.StatusFail,
				Category:    "pss",
				Resource:    resource,
				Namespace:   namespace,
				Remediation: "Set securityContext.runAsNonRoot: true or specify a non-root runAsUser at the pod or container level.",
				Details: map[string]string{
					"container": container.Name,
					"profile":   string(ProfileRestricted),
				},
				Timestamp: now,
			})
		}
	}

	return findings
}

// checkSeccompProfile verifies seccomp profiles are set.
func (c *Checker) checkSeccompProfile(spec *corev1.PodSpec, resource, namespace string, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	podHasSeccomp := spec.SecurityContext != nil &&
		spec.SecurityContext.SeccompProfile != nil &&
		(spec.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeRuntimeDefault ||
			spec.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeLocalhost)

	for _, container := range allContainers(spec) {
		containerHasSeccomp := container.SecurityContext != nil &&
			container.SecurityContext.SeccompProfile != nil &&
			(container.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeRuntimeDefault ||
				container.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeLocalhost)

		if !podHasSeccomp && !containerHasSeccomp {
			findings = append(findings, scanner.Finding{
				ID:          "PSS-R002",
				Title:       "Missing seccomp profile",
				Description: fmt.Sprintf("Container %q in %s does not have a seccomp profile set (RuntimeDefault or Localhost required)", container.Name, resource),
				Severity:    scanner.SeverityMedium,
				Status:      scanner.StatusFail,
				Category:    "pss",
				Resource:    resource,
				Namespace:   namespace,
				Remediation: "Set securityContext.seccompProfile.type to RuntimeDefault or Localhost.",
				Details: map[string]string{
					"container": container.Name,
					"profile":   string(ProfileRestricted),
				},
				Timestamp: now,
			})
		}
	}

	return findings
}

// checkDropAllCapabilities verifies all capabilities are dropped (Restricted).
func (c *Checker) checkDropAllCapabilities(spec *corev1.PodSpec, resource, namespace string, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	for _, container := range allContainers(spec) {
		dropsAll := false
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			for _, cap := range container.SecurityContext.Capabilities.Drop {
				if strings.EqualFold(string(cap), "ALL") {
					dropsAll = true
					break
				}
			}
		}

		if !dropsAll {
			findings = append(findings, scanner.Finding{
				ID:          "PSS-R003",
				Title:       "Capabilities not dropped",
				Description: fmt.Sprintf("Container %q in %s does not drop ALL capabilities", container.Name, resource),
				Severity:    scanner.SeverityMedium,
				Status:      scanner.StatusFail,
				Category:    "pss",
				Resource:    resource,
				Namespace:   namespace,
				Remediation: "Set securityContext.capabilities.drop: [ALL]. You may then add back only NET_BIND_SERVICE if needed.",
				Details: map[string]string{
					"container": container.Name,
					"profile":   string(ProfileRestricted),
				},
				Timestamp: now,
			})
		}
	}

	return findings
}

// checkAllowPrivilegeEscalation verifies allowPrivilegeEscalation is false.
func (c *Checker) checkAllowPrivilegeEscalation(spec *corev1.PodSpec, resource, namespace string, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	for _, container := range allContainers(spec) {
		// Default is true when not set, so must be explicitly false.
		if container.SecurityContext == nil ||
			container.SecurityContext.AllowPrivilegeEscalation == nil ||
			*container.SecurityContext.AllowPrivilegeEscalation {
			findings = append(findings, scanner.Finding{
				ID:          "PSS-R004",
				Title:       "Privilege escalation allowed",
				Description: fmt.Sprintf("Container %q in %s allows privilege escalation (allowPrivilegeEscalation is not set to false)", container.Name, resource),
				Severity:    scanner.SeverityMedium,
				Status:      scanner.StatusFail,
				Category:    "pss",
				Resource:    resource,
				Namespace:   namespace,
				Remediation: "Set securityContext.allowPrivilegeEscalation: false.",
				Details: map[string]string{
					"container": container.Name,
					"profile":   string(ProfileRestricted),
				},
				Timestamp: now,
			})
		}
	}

	return findings
}

// checkReadOnlyRootFilesystem verifies the root filesystem is read-only.
func (c *Checker) checkReadOnlyRootFilesystem(spec *corev1.PodSpec, resource, namespace string, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	for _, container := range allContainers(spec) {
		if container.SecurityContext == nil ||
			container.SecurityContext.ReadOnlyRootFilesystem == nil ||
			!*container.SecurityContext.ReadOnlyRootFilesystem {
			findings = append(findings, scanner.Finding{
				ID:          "PSS-R005",
				Title:       "Root filesystem is writable",
				Description: fmt.Sprintf("Container %q in %s does not have a read-only root filesystem", container.Name, resource),
				Severity:    scanner.SeverityLow,
				Status:      scanner.StatusWarning,
				Category:    "pss",
				Resource:    resource,
				Namespace:   namespace,
				Remediation: "Set securityContext.readOnlyRootFilesystem: true and use emptyDir or tmpfs volumes for writable paths.",
				Details: map[string]string{
					"container": container.Name,
					"profile":   string(ProfileRestricted),
				},
				Timestamp: now,
			})
		}
	}

	return findings
}

// CheckDeployment evaluates a single Deployment's pod template against PSS.
// This is exported for use by the scanner when checking individual resources.
func (c *Checker) CheckDeployment(deploy *appsv1.Deployment, now time.Time) []scanner.Finding {
	resource := fmt.Sprintf("Deployment/%s/%s", deploy.Namespace, deploy.Name)
	return c.checkPodSpec(&deploy.Spec.Template.Spec, resource, deploy.Namespace, now)
}

// CheckPod evaluates a single Pod against PSS.
func (c *Checker) CheckPod(pod *corev1.Pod, now time.Time) []scanner.Finding {
	resource := fmt.Sprintf("Pod/%s/%s", pod.Namespace, pod.Name)
	return c.checkPodSpec(&pod.Spec, resource, pod.Namespace, now)
}
