// Package k8s provides a read-only Kubernetes client wrapper for compliance
// scanning operations.
package k8s

import (
	"context"
	"fmt"
	"log/slog"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps the Kubernetes client-go with convenience methods for
// listing common resources. All operations are read-only.
type Client struct {
	clientset   kubernetes.Interface
	clusterName string
	logger      *slog.Logger
}

// NewClient creates a new Kubernetes client from a kubeconfig path.
// If kubeconfigPath is empty, it attempts in-cluster configuration.
func NewClient(kubeconfigPath string, logger *slog.Logger) (*Client, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var config *rest.Config
	var clusterName string
	var err error

	if kubeconfigPath != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("building config from kubeconfig %s: %w", kubeconfigPath, err)
		}
		// Extract cluster name from kubeconfig.
		kubeConfig, loadErr := clientcmd.LoadFromFile(kubeconfigPath)
		if loadErr == nil && kubeConfig.CurrentContext != "" {
			if ctx, ok := kubeConfig.Contexts[kubeConfig.CurrentContext]; ok {
				clusterName = ctx.Cluster
			}
		}
		logger.Info("using kubeconfig", "path", kubeconfigPath, "cluster", clusterName)
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("building in-cluster config: %w", err)
		}
		clusterName = "in-cluster"
		logger.Info("using in-cluster configuration")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes clientset: %w", err)
	}

	return &Client{
		clientset:   clientset,
		clusterName: clusterName,
		logger:      logger,
	}, nil
}

// NewClientFromInterface creates a Client from an existing kubernetes.Interface.
// Useful for testing with fake clients.
func NewClientFromInterface(cs kubernetes.Interface, clusterName string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		clientset:   cs,
		clusterName: clusterName,
		logger:      logger,
	}
}

// Clientset returns the underlying kubernetes.Interface.
func (c *Client) Clientset() kubernetes.Interface {
	return c.clientset
}

// ClusterName returns the name of the connected cluster.
func (c *Client) ClusterName() string {
	return c.clusterName
}

// ListNamespaces returns all namespaces in the cluster.
func (c *Client) ListNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	list, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	c.logger.Debug("listed namespaces", "count", len(list.Items))
	return list.Items, nil
}

// ListPods returns pods in the given namespace. Empty namespace means all namespaces.
func (c *Client) ListPods(ctx context.Context, namespace string) ([]corev1.Pod, error) {
	list, err := c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods in namespace %q: %w", namespace, err)
	}
	c.logger.Debug("listed pods", "namespace", namespace, "count", len(list.Items))
	return list.Items, nil
}

// ListServices returns services in the given namespace. Empty namespace means all namespaces.
func (c *Client) ListServices(ctx context.Context, namespace string) ([]corev1.Service, error) {
	list, err := c.clientset.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing services in namespace %q: %w", namespace, err)
	}
	c.logger.Debug("listed services", "namespace", namespace, "count", len(list.Items))
	return list.Items, nil
}

// ListNodes returns all nodes in the cluster.
func (c *Client) ListNodes(ctx context.Context) ([]corev1.Node, error) {
	list, err := c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing nodes: %w", err)
	}
	c.logger.Debug("listed nodes", "count", len(list.Items))
	return list.Items, nil
}

// ListClusterRoles returns all ClusterRoles.
func (c *Client) ListClusterRoles(ctx context.Context) ([]rbacv1.ClusterRole, error) {
	list, err := c.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing cluster roles: %w", err)
	}
	c.logger.Debug("listed cluster roles", "count", len(list.Items))
	return list.Items, nil
}

// ListClusterRoleBindings returns all ClusterRoleBindings.
func (c *Client) ListClusterRoleBindings(ctx context.Context) ([]rbacv1.ClusterRoleBinding, error) {
	list, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing cluster role bindings: %w", err)
	}
	c.logger.Debug("listed cluster role bindings", "count", len(list.Items))
	return list.Items, nil
}

// ListRoles returns Roles in the given namespace. Empty namespace means all namespaces.
func (c *Client) ListRoles(ctx context.Context, namespace string) ([]rbacv1.Role, error) {
	list, err := c.clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing roles in namespace %q: %w", namespace, err)
	}
	c.logger.Debug("listed roles", "namespace", namespace, "count", len(list.Items))
	return list.Items, nil
}

// ListRoleBindings returns RoleBindings in the given namespace. Empty namespace means all namespaces.
func (c *Client) ListRoleBindings(ctx context.Context, namespace string) ([]rbacv1.RoleBinding, error) {
	list, err := c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing role bindings in namespace %q: %w", namespace, err)
	}
	c.logger.Debug("listed role bindings", "namespace", namespace, "count", len(list.Items))
	return list.Items, nil
}

// ListNetworkPolicies returns NetworkPolicies in the given namespace. Empty namespace means all namespaces.
func (c *Client) ListNetworkPolicies(ctx context.Context, namespace string) ([]networkingv1.NetworkPolicy, error) {
	list, err := c.clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing network policies in namespace %q: %w", namespace, err)
	}
	c.logger.Debug("listed network policies", "namespace", namespace, "count", len(list.Items))
	return list.Items, nil
}

// ListDeployments returns Deployments in the given namespace. Empty namespace means all namespaces.
func (c *Client) ListDeployments(ctx context.Context, namespace string) ([]appsv1.Deployment, error) {
	list, err := c.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing deployments in namespace %q: %w", namespace, err)
	}
	c.logger.Debug("listed deployments", "namespace", namespace, "count", len(list.Items))
	return list.Items, nil
}

// ListDaemonSets returns DaemonSets in the given namespace. Empty namespace means all namespaces.
func (c *Client) ListDaemonSets(ctx context.Context, namespace string) ([]appsv1.DaemonSet, error) {
	list, err := c.clientset.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing daemonsets in namespace %q: %w", namespace, err)
	}
	c.logger.Debug("listed daemonsets", "namespace", namespace, "count", len(list.Items))
	return list.Items, nil
}

// ListStatefulSets returns StatefulSets in the given namespace. Empty namespace means all namespaces.
func (c *Client) ListStatefulSets(ctx context.Context, namespace string) ([]appsv1.StatefulSet, error) {
	list, err := c.clientset.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing statefulsets in namespace %q: %w", namespace, err)
	}
	c.logger.Debug("listed statefulsets", "namespace", namespace, "count", len(list.Items))
	return list.Items, nil
}

// ListSecrets returns Secrets in the given namespace. Empty namespace means all namespaces.
func (c *Client) ListSecrets(ctx context.Context, namespace string) ([]corev1.Secret, error) {
	list, err := c.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing secrets in namespace %q: %w", namespace, err)
	}
	c.logger.Debug("listed secrets", "namespace", namespace, "count", len(list.Items))
	return list.Items, nil
}

// GetSecret retrieves a single Secret by name from the given namespace.
func (c *Client) GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	secret, err := c.clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting secret %s/%s: %w", namespace, name, err)
	}
	return secret, nil
}

// NamespacesForScan returns the list of namespaces to scan. If the provided
// list is non-empty, it is returned as-is. Otherwise, all cluster namespaces
// are returned (excluding kube-system and kube-public by default).
func (c *Client) NamespacesForScan(ctx context.Context, requested []string, includeSystem bool) ([]string, error) {
	if len(requested) > 0 {
		return requested, nil
	}

	namespaces, err := c.ListNamespaces(ctx)
	if err != nil {
		return nil, err
	}

	systemNamespaces := map[string]bool{
		"kube-system": true,
		"kube-public": true,
		"kube-node-lease": true,
	}

	var result []string
	for _, ns := range namespaces {
		if !includeSystem && systemNamespaces[ns.Name] {
			continue
		}
		result = append(result, ns.Name)
	}

	return result, nil
}

// ListPodsJSON returns pods as generic interface{} values suitable for OPA evaluation.
// This satisfies the scanner.ResourceLister interface.
func (c *Client) ListPodsJSON(ctx context.Context, namespace string) ([]interface{}, error) {
	pods, err := c.ListPods(ctx, namespace)
	if err != nil {
		return nil, err
	}
	result := make([]interface{}, len(pods))
	for i := range pods {
		result[i] = pods[i]
	}
	return result, nil
}

// ListDeploymentsJSON returns deployments as generic interface{} values suitable for OPA evaluation.
// This satisfies the scanner.ResourceLister interface.
func (c *Client) ListDeploymentsJSON(ctx context.Context, namespace string) ([]interface{}, error) {
	deployments, err := c.ListDeployments(ctx, namespace)
	if err != nil {
		return nil, err
	}
	result := make([]interface{}, len(deployments))
	for i := range deployments {
		result[i] = deployments[i]
	}
	return result, nil
}
