package pressure

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/alitto/pond/v2"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	cmdTimeout   = 1800 * time.Second
	k8sTimeout   = 60 * time.Second
	warningRatio = 0.8

	globalsDir    = "/sys/fs/bpf/tc/globals"
	podNamePrefix = "bpf-inspector"
	containerName = podNamePrefix
	inspectNS     = "bpf-inspect"
)

var (
	bpfMapNames = []string{"cilium_ct4_global", "cilium_ct6_global", "cilium_ct_any4_global", "cilium_ct_any6_global",
		"cilium_nodeport_neigh4", "cilium_nodeport_neigh6", "cilium_snat_v4_external", "cilium_snat_v6_external",
	}
	shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}
)

type bpfMapStatus string

const (
	Unknown bpfMapStatus = "[Unknown]"
	OK      bpfMapStatus = "[O.K.]"
	Warning bpfMapStatus = "[Warning]"
)

type bpfMap struct {
	name           string
	maxEntries     int
	currentEntries int
	usage          float64
	status         bpfMapStatus
	errMsg         string
}

type node struct {
	name    string
	bpfMaps map[string]*bpfMap
}

type Scanner struct {
	kc      *kubernetes.Clientset
	restCfg *rest.Config

	mu    sync.RWMutex
	nodes map[string]*node
}

func NewScanner(kc *kubernetes.Clientset, restCfg *rest.Config, kubeconfig string) (*Scanner, error) {
	if kc == nil || restCfg == nil {
		if kubeconfig == "" {
			kubeconfig = os.ExpandEnv("$HOME/.kube/config")
		}
		if kubeconfig == "" {
			kubeconfig = os.Getenv("KUBECONFIG")
		}
		var err error
		kc, restCfg, err = kubernetesClient(kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
		}
	}

	return &Scanner{
		kc:      kc,
		restCfg: restCfg,
		nodes:   make(map[string]*node),
	}, nil
}

func (s *Scanner) Validate() (err error) {
	return nil
}

func (s *Scanner) Run(targetNodeName string) error {
	const poolSize = 10

	nodes, err := s.listNodes(targetNodeName)
	if err != nil {
		return fmt.Errorf("failed to get nodes: %w", err)
	}

	err = s.ensureInspectNS()
	if err != nil {
		fmt.Printf("Failed to create namespace %s: %v\n", inspectNS, err)
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), shutdownSignals...)
	shutdownWG := &sync.WaitGroup{}
	shutdownWG.Add(1)
	go s.startShutdownHandler(ctx, shutdownWG, nodes)

	pool := pond.NewPool(poolSize, pond.WithContext(ctx))
	for _, node := range nodes {
		pool.Submit(func() {
			s.inspectNode(ctx, node)
		})
	}
	pool.StopAndWait()

	err = s.printResult()
	if err != nil {
		return fmt.Errorf("failed to print results: %w", err)
	}

	/* Trigger shutdown handler */
	cancel()
	shutdownWG.Wait()

	return nil
}

func (s *Scanner) listNodes(targetNodeName string) ([]corev1.Node, error) {
	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	nodes, err := s.kc.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	if targetNodeName != "" {
		var filteredNodes []corev1.Node
		for _, node := range nodes.Items {
			if node.Name == targetNodeName {
				filteredNodes = append(filteredNodes, node)
			}
		}
		nodes.Items = filteredNodes
	}

	if len(nodes.Items) == 0 {
		return nil, fmt.Errorf("no nodes found")
	}

	return nodes.Items, nil
}

func (s *Scanner) startShutdownHandler(sigCtx context.Context, wg *sync.WaitGroup, nodes []corev1.Node) {
	<-sigCtx.Done()
	signal.Ignore(shutdownSignals...)
	defer wg.Done()

	fmt.Println("\033[33mPlease wait for cleanup to complete...\033[0m")

	for _, node := range nodes {
		inspectorPodName := fmt.Sprintf("%s-%s", podNamePrefix, node.Name)
		s.deletePod(inspectorPodName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, k8sTimeout, true, func(ctx context.Context) (bool, error) {
		pods, err := s.kc.CoreV1().Pods(inspectNS).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, fmt.Errorf("failed to list pods: %w", err)
		}
		if len(pods.Items) == 0 {
			return true, nil
		}
		fmt.Printf("\033[33mWaiting for inspector pods to be deleted... Remaining pods: %d\033[0m\n", len(pods.Items))
		return false, nil
	})
	if err != nil {
		fmt.Printf("Error waiting for pods to be deleted: %v\n", err)
		return
	}

	err = s.deleteInspectorNamespace()
	if err != nil {
		fmt.Printf("Error deleting namespace %s: %v\n", inspectNS, err)
		return
	}

	fmt.Println("\033[33mAll inspector pods deleted successfully.\033[0m")
}

func (s *Scanner) inspectNode(ctx context.Context, node corev1.Node) {
	fmt.Printf("Inspecting node... %s\n", node.Name)

	inspectorPod, err := s.ensureInspectorPod(ctx, node.Name)
	if err != nil {
		fmt.Printf("Failed to ensure inspector pod on node %s: %v\n", node.Name, err)
	}
	defer s.deletePod(inspectorPod.Name)

	n := newNode(node.Name)
	s.filterExistingBpfMaps(ctx, n, inspectorPod)

	for mapName, bpfMap := range n.bpfMaps {
		fmt.Printf("Inspecting BPF map... %s in node: %s\n", mapName, node.Name)
		bpfMapStats, err := s.getBpfMapStats(ctx, inspectorPod, mapName)
		if err != nil {
			bpfMap.errMsg = err.Error()
			continue
		}
		n.bpfMaps[mapName] = bpfMapStats
	}

	s.mu.Lock()
	s.nodes[node.Name] = n
	s.mu.Unlock()
}

func (s *Scanner) ensureInspectNS() error {
	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: inspectNS,
		},
	}

	_, err := s.kc.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create namespace %s: %w", namespace.Name, err)
	}

	return nil
}

func (s *Scanner) deleteInspectorNamespace() error {
	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	err := s.kc.CoreV1().Namespaces().Delete(ctx, inspectNS, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete namespace %s: %w", inspectNS, err)
	}

	return nil
}

func (s *Scanner) deletePod(podName string) {
	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	err := s.kc.CoreV1().Pods(inspectNS).Delete(ctx, podName, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		fmt.Printf("failed to delete pod %s: %v\n", podName, err)
	}
}

func (s *Scanner) getBpfMapStats(ctx context.Context, pod *corev1.Pod, mapName string) (*bpfMap, error) {
	cmd := []string{"sh", "-c",
		fmt.Sprintf("bpftool map show pinned %s/%s | grep -o 'max_entries [0-9]\\+' | awk '{print $2}'", globalsDir, mapName),
	}
	result, err := s.execCmd(ctx, pod, cmd)
	if err != nil {
		return nil, err
	}
	maxEntries, err := strconv.Atoi(result)
	if err != nil {
		return nil, err
	}

	cmd = []string{"sh", "-c",
		fmt.Sprintf("bpftool map dump pinned %s/%s | grep element | awk '{print $2}'", globalsDir, mapName),
	}
	result, err = s.execCmd(ctx, pod, cmd)
	if err != nil {
		return nil, err
	}
	currentEntries, err := strconv.Atoi(result)
	if err != nil {
		return nil, err
	}

	usage := float64(currentEntries) / float64(maxEntries) * 100
	var status bpfMapStatus

	if currentEntries >= int(float64(maxEntries)*warningRatio) {
		status = Warning
	} else {
		status = OK
	}

	bpfMap := &bpfMap{
		maxEntries:     maxEntries,
		currentEntries: currentEntries,
		usage:          usage,
		status:         status,
	}

	return bpfMap, nil
}

func (s *Scanner) filterExistingBpfMaps(ctx context.Context, n *node, inspectorPod *corev1.Pod) {
	for _, mapName := range bpfMapNames {
		exist, err := s.existBpfMap(ctx, inspectorPod, mapName)
		if err != nil {
			n.bpfMaps[mapName].errMsg = err.Error()
			continue
		} else if !exist {
			/* If the map does not exist, skip it. e.g.) ipv6 */
			delete(n.bpfMaps, mapName)
			continue
		}
	}
}

func (s *Scanner) existBpfMap(ctx context.Context, inspectorPod *corev1.Pod, mapName string) (bool, error) {
	cmd := []string{"sh", "-c", fmt.Sprintf("[ -f %s/%s ]", globalsDir, mapName)}
	_, err := s.execCmd(ctx, inspectorPod, cmd)
	if err != nil {
		// Error
		if !strings.Contains(err.Error(), "exit code 1") {
			return false, err
		}
		// Not exist
		return false, nil
	}
	// Exist
	return true, nil
}

func (s *Scanner) printResult() error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	lines := map[bpfMapStatus][]string{
		Unknown: {},
		OK:      {},
		Warning: {},
	}

	// Organize output by status
	for nodeName, node := range s.nodes {
		for mapName, bpfMap := range node.bpfMaps {
			var line string
			if bpfMap.status == Unknown {
				line = fmt.Sprintf("%s\t%s\t%s\tERR:%s\n", Unknown, nodeName, mapName, bpfMap.errMsg)
			} else {
				line = fmt.Sprintf("%s\t%s\t%s\t%.2f%%\t%d/%d\n",
					bpfMap.status, nodeName, mapName, bpfMap.usage, bpfMap.currentEntries, bpfMap.maxEntries)
			}
			lines[bpfMap.status] = append(lines[bpfMap.status], line)
		}
	}

	// Print results
	fmt.Fprintf(w, "%s", "\nSTATUS\tNODE\tMAP\tUSAGE\tCURRENT/MAX\n")
	fmt.Fprintf(w, "%s", strings.Join(lines[Warning], ""))
	fmt.Fprintf(w, "%s", strings.Join(lines[OK], ""))
	fmt.Fprintf(w, "%s", strings.Join(lines[Unknown], ""))

	err := w.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush tab writer: %w", err)
	}

	if len(lines[Warning]) > 0 {
		fmt.Printf("\n\033[38;5;208mIf you see [Warning] status in the output and encounter network issues,\n" +
			"Please consider increasing --bpf-map-dynamic-size-ratio in cilium-agent configuration.\033[0m\n\n")
	}
	return nil
}

func (s *Scanner) ensureInspectorPod(parentCtx context.Context, nodeName string) (*corev1.Pod, error) {
	const (
		imageName      = "gyutaeb/bpftool:v7.5.0"
		bpffsMountPath = "/sys/fs/bpf"
		cpuRequest     = "0"
		cpuLimit       = "200m"
	)
	var (
		capabilities    = []corev1.Capability{"SYS_ADMIN", "SYS_RESOURCE", "NET_ADMIN", "NET_RAW"}
		privileged      = true
		hostToContainer = corev1.MountPropagationHostToContainer
	)

	podName := fmt.Sprintf("%s-%s", podNamePrefix, nodeName)
	inspectorPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: inspectNS,
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
			Containers: []corev1.Container{
				{
					Name:    containerName,
					Image:   imageName,
					Command: []string{"sleep", "infinity"},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU: resource.MustParse(cpuRequest),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU: resource.MustParse(cpuLimit),
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged: &privileged,
						Capabilities: &corev1.Capabilities{
							Add: capabilities,
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:             "bpffs",
							MountPath:        bpffsMountPath,
							ReadOnly:         true,
							MountPropagation: &hostToContainer,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "bpffs",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: bpffsMountPath,
						},
					},
				},
			},
			Tolerations: []corev1.Toleration{
				{
					Operator: corev1.TolerationOpExists,
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(parentCtx, k8sTimeout)
	defer cancel()

	createdPod, err := s.kc.CoreV1().Pods(inspectNS).Create(ctx, inspectorPod, metav1.CreateOptions{})
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("failed to create inspector pod: %w", err)
		}
		createdPod = inspectorPod
	}

	fmt.Printf("Created inspector pod: %s\n", createdPod.Name)

	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, k8sTimeout, true, func(ctx context.Context) (bool, error) {
		pod, err := s.kc.CoreV1().Pods(inspectNS).Get(ctx, createdPod.Name, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("failed to get inspector pod: %w", err)
		}
		if pod.Status.Phase == corev1.PodRunning {
			return true, nil
		}
		return false, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to wait for inspector pod to be running: %w", err)
	}

	return createdPod, nil
}

func (s *Scanner) execCmd(parentCtx context.Context, pod *corev1.Pod, cmd []string) (string, error) {
	req := s.kc.CoreV1().RESTClient().Post().Namespace(inspectNS).Resource("pods").
		Name(pod.Name).SubResource("exec").VersionedParams(&corev1.PodExecOptions{
		Container: containerName,
		Command:   cmd,
		Stdout:    true,
		Stderr:    true,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(s.restCfg, "POST", req.URL())
	if err != nil {
		fmt.Printf("[Pre-exec-error] pod:%s, node:%s, err:%v\n", pod.Name, pod.Spec.NodeName, err)
		return "", err
	}

	var stdout, stderr bytes.Buffer
	ctx, cancle := context.WithTimeout(parentCtx, cmdTimeout)
	defer cancle()

	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(stdout.String()), nil
}

func newNode(nodeName string) *node {
	n := &node{
		name:    nodeName,
		bpfMaps: make(map[string]*bpfMap),
	}

	for _, mapName := range bpfMapNames {
		n.bpfMaps[mapName] = &bpfMap{
			name:   mapName,
			status: Unknown,
		}
	}

	return n
}

func kubernetesClient(kubeConfig string) (*kubernetes.Clientset, *rest.Config, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		return nil, nil, err
	}

	kc, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	return kc, config, nil
}
