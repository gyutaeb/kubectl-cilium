package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/alitto/pond/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	execTimeout  = 10 * time.Second
	poolSize     = 10
	warningRatio = 0.8
)

type NodeInfo struct {
	NodeName   string
	PodName    string
	MaxCnt     int
	CurrentCnt int
	Usage      float64
}

type nodeGroup struct {
	mu    sync.Mutex
	nodes []NodeInfo
}

type Scanner struct {
	kc      *kubernetes.Clientset
	restCfg *rest.Config

	warningNodes nodeGroup
	normalNodes  nodeGroup
	unknownNodes nodeGroup
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
		kc:           kc,
		restCfg:      restCfg,
		warningNodes: nodeGroup{},
		normalNodes:  nodeGroup{},
		unknownNodes: nodeGroup{},
	}, nil
}

func (s *Scanner) Validate() (err error) {
	return nil
}

func (s *Scanner) Run(nodename string) error {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	ciliumPods, err := s.kc.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
	if err != nil {
		return fmt.Errorf("failed to list Cilium pods: %w", err)
	}
	if nodename != "" {
		var filteredPods []corev1.Pod
		for _, pod := range ciliumPods.Items {
			if pod.Spec.NodeName == nodename {
				filteredPods = append(filteredPods, pod)
			}
		}
		ciliumPods.Items = filteredPods
	}

	pool := pond.NewPool(poolSize)
	for _, pod := range ciliumPods.Items {
		pool.Submit(func() {
			s.processPod(pod)
		})
	}
	pool.StopAndWait()

	err = s.print()
	if err != nil {
		return fmt.Errorf("failed to print results: %w", err)
	}
	return nil
}

func (s *Scanner) print() error {
	sort.Slice(s.warningNodes.nodes, func(i, j int) bool {
		return s.warningNodes.nodes[i].Usage > s.warningNodes.nodes[j].Usage
	})
	sort.Slice(s.normalNodes.nodes, func(i, j int) bool {
		return s.normalNodes.nodes[i].Usage > s.normalNodes.nodes[j].Usage
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "\nSTATUS\tNODE\tCILIUM-POD\tSNAT-MAP-USAGE\tCURRENT/MAX\n")
	for _, node := range s.warningNodes.nodes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%.2f%%\t%d/%d\n", "[Warning]", node.NodeName, node.PodName, node.Usage, node.CurrentCnt, node.MaxCnt)
	}
	for _, node := range s.normalNodes.nodes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%.2f%%\t%d/%d\n", "[O.K.]", node.NodeName, node.PodName, node.Usage, node.CurrentCnt, node.MaxCnt)
	}
	for _, node := range s.unknownNodes.nodes {
		fmt.Fprintf(w, "%s\t%s\t%s\n", "[Unknown]", node.NodeName, node.PodName)
	}

	err := w.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush tab writer: %w", err)
	}
	return nil
}

func (s *Scanner) processPod(pod corev1.Pod) (err error) {
	defer func() {
		if err != nil {
			s.unknownNodes.mu.Lock()
			s.unknownNodes.nodes = append(s.unknownNodes.nodes, NodeInfo{
				NodeName: pod.Spec.NodeName,
				PodName:  pod.Name,
			})
			s.unknownNodes.mu.Unlock()
		}
	}()
	fmt.Printf("Checking node... %s, cilium pod: %s\n", pod.Spec.NodeName, pod.Name)

	cmd := []string{"sh", "-c", "bpftool map show pinned /sys/fs/bpf/tc/globals/cilium_snat_v4_external | grep -o 'max_entries [0-9]\\+' | awk '{print $2}'"}
	result, err := s.execCmd(&pod, cmd)
	if err != nil {
		return err
	}
	maxCnt, err := strconv.Atoi(result)
	if err != nil {
		return err
	}

	cmd = []string{"sh", "-c", "bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_snat_v4_external | grep elements | awk '{print $2}'"}
	result, err = s.execCmd(&pod, cmd)
	if err != nil {
		return err
	}
	currentCnt, err := strconv.Atoi(result)
	if err != nil {
		return err
	}

	if currentCnt >= int(float64(maxCnt)*warningRatio) {
		s.warningNodes.mu.Lock()
		s.warningNodes.nodes = append(s.warningNodes.nodes, NodeInfo{
			NodeName:   pod.Spec.NodeName,
			PodName:    pod.Name,
			MaxCnt:     maxCnt,
			CurrentCnt: currentCnt,
			Usage:      float64(currentCnt) / float64(maxCnt) * 100,
		})
		s.warningNodes.mu.Unlock()
	} else {
		s.normalNodes.mu.Lock()
		s.normalNodes.nodes = append(s.normalNodes.nodes, NodeInfo{
			NodeName:   pod.Spec.NodeName,
			PodName:    pod.Name,
			MaxCnt:     maxCnt,
			CurrentCnt: currentCnt,
			Usage:      float64(currentCnt) / float64(maxCnt) * 100,
		})
		s.normalNodes.mu.Unlock()
	}

	return nil
}

func (s *Scanner) execCmd(pod *corev1.Pod, cmd []string) (string, error) {
	req := s.kc.CoreV1().RESTClient().Post().Namespace("kube-system").Resource("pods").
		Name(pod.Name).SubResource("exec").VersionedParams(&corev1.PodExecOptions{
		Container: "cilium-agent",
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
	ctx, cancle := context.WithTimeout(context.Background(), execTimeout)
	defer cancle()

	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		fmt.Printf("[Exec-error] pod:%s, node:%s, stderr:%s, err:%v\n", pod.Name, pod.Spec.NodeName, stderr.String(), err)
		return "", err
	}

	return strings.TrimSpace(stdout.String()), nil
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
