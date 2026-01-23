//go:build linux

package cmd

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"ztap/pkg/enforcer"
)

type k8sSubjectResolver struct {
	client     kubernetes.Interface
	cgroupRoot string
}

func newK8sSubjectResolver(client kubernetes.Interface, cgroupRoot string) enforcer.SubjectResolver {
	cgroupRoot = strings.TrimSpace(cgroupRoot)
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	return &k8sSubjectResolver{client: client, cgroupRoot: cgroupRoot}
}

func (r *k8sSubjectResolver) ResolveCgroupIDs(ctx context.Context, tenant string, podSelector map[string]string) ([]uint64, error) {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		tenant = "default"
	}

	sel := labels.Set(podSelector).AsSelector().String()
	pods, err := r.client.CoreV1().Pods(tenant).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, err
	}
	if len(pods.Items) == 0 {
		return []uint64{}, nil
	}

	ids := make([]uint64, 0, len(pods.Items))
	seen := make(map[uint64]struct{}, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		containerIDs := extractContainerIDs(pod)
		for _, cid := range containerIDs {
			cgPath, err := findContainerCgroupPath(r.cgroupRoot, pod, cid)
			if err != nil {
				continue
			}
			cgid, err := cgroupIDFromPath(cgPath)
			if err != nil {
				continue
			}
			if _, ok := seen[cgid]; ok {
				continue
			}
			seen[cgid] = struct{}{}
			ids = append(ids, cgid)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("matched %d pods but resolved 0 cgroup IDs (namespace=%s selector=%s)", len(pods.Items), tenant, sel)
	}

	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func extractContainerIDs(pod *corev1.Pod) []string {
	ids := make([]string, 0)
	add := func(cid string) {
		cid = strings.TrimSpace(cid)
		if cid == "" {
			return
		}
		if parts := strings.SplitN(cid, "://", 2); len(parts) == 2 {
			cid = parts[1]
		}
		cid = strings.TrimSpace(cid)
		if cid == "" {
			return
		}
		ids = append(ids, cid)
	}

	for _, st := range pod.Status.InitContainerStatuses {
		add(st.ContainerID)
	}
	for _, st := range pod.Status.ContainerStatuses {
		add(st.ContainerID)
	}
	for _, st := range pod.Status.EphemeralContainerStatuses {
		add(st.ContainerID)
	}
	return ids
}

func cgroupIDFromPath(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unexpected stat type for %s", path)
	}
	return st.Ino, nil
}

func findContainerCgroupPath(cgroupRoot string, pod *corev1.Pod, containerID string) (string, error) {
	uid := string(pod.UID)
	uidUnderscore := strings.ReplaceAll(uid, "-", "_")
	uidVars := []string{uid, uidUnderscore}

	scopes := []string{
		"cri-containerd-" + containerID + ".scope",
		"docker-" + containerID + ".scope",
		"crio-" + containerID + ".scope",
		"cri-o-" + containerID + ".scope",
		containerID,
	}

	qos := pod.Status.QOSClass
	if qos == "" {
		qos = corev1.PodQOSBurstable
	}

	var candidates []string
	for _, u := range uidVars {
		podToken := "pod" + u

		// systemd driver
		kubepodsSlice := filepath.Join(cgroupRoot, "kubepods.slice")
		systemdPodDirs := []string{}
		switch qos {
		case corev1.PodQOSBestEffort:
			systemdPodDirs = append(systemdPodDirs,
				filepath.Join(kubepodsSlice, "kubepods-besteffort.slice", "kubepods-besteffort-"+podToken+".slice"),
			)
		case corev1.PodQOSGuaranteed:
			systemdPodDirs = append(systemdPodDirs,
				filepath.Join(kubepodsSlice, "kubepods-"+podToken+".slice"),
			)
		default:
			systemdPodDirs = append(systemdPodDirs,
				filepath.Join(kubepodsSlice, "kubepods-burstable.slice", "kubepods-burstable-"+podToken+".slice"),
			)
		}
		for _, base := range systemdPodDirs {
			for _, scope := range scopes {
				candidates = append(candidates, filepath.Join(base, scope))
			}
		}

		// cgroupfs driver
		kubepods := filepath.Join(cgroupRoot, "kubepods")
		cgroupfsPodDirs := []string{}
		switch qos {
		case corev1.PodQOSBestEffort:
			cgroupfsPodDirs = append(cgroupfsPodDirs, filepath.Join(kubepods, "besteffort", podToken))
		case corev1.PodQOSGuaranteed:
			cgroupfsPodDirs = append(cgroupfsPodDirs, filepath.Join(kubepods, podToken))
		default:
			cgroupfsPodDirs = append(cgroupfsPodDirs, filepath.Join(kubepods, "burstable", podToken))
		}
		for _, base := range cgroupfsPodDirs {
			for _, scope := range scopes {
				candidates = append(candidates, filepath.Join(base, scope))
			}
		}
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	// Bounded fallback scan under common roots.
	roots := []string{filepath.Join(cgroupRoot, "kubepods.slice"), filepath.Join(cgroupRoot, "kubepods")}
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		found, ok := walkFindContainerCgroup(root, uidVars, containerID)
		if ok {
			return found, nil
		}
	}

	return "", fmt.Errorf("unable to locate cgroup for pod %s container %s", pod.Name, containerID)
}

func walkFindContainerCgroup(root string, uidVars []string, containerID string) (string, bool) {
	max := 8000
	seen := 0
	var found string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		seen++
		if seen > max {
			return fs.SkipAll
		}
		if !d.IsDir() {
			return nil
		}
		if !strings.Contains(path, containerID) {
			return nil
		}
		for _, u := range uidVars {
			if strings.Contains(path, "pod"+u) {
				found = path
				return fs.SkipAll
			}
		}
		return nil
	})
	if found == "" {
		return "", false
	}
	return found, true
}
