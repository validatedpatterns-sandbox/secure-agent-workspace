package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	core "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

func (c *controller) qga(ctx context.Context, ns, pod, domain string, request interface{}) (map[string]interface{}, error) {
	raw, _ := json.Marshal(request)
	cmd := []string{"virsh", "-c", "qemu:///session", "qemu-agent-command", domain, string(raw)}
	req := c.k.CoreV1().RESTClient().Post().Resource("pods").Namespace(ns).Name(pod).SubResource("exec").VersionedParams(&core.PodExecOptions{Container: "compute", Command: cmd, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return nil, fmt.Errorf("guest diagnostic transport unavailable")
	}
	var out, stderr bytes.Buffer
	if err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &out, Stderr: &stderr}); err != nil {
		return nil, fmt.Errorf("guest diagnostic unavailable: %s", diagnosticText(err))
	}
	var result struct {
		Return map[string]interface{} `json:"return"`
		Error  interface{}            `json:"error"`
	}
	if json.Unmarshal(out.Bytes(), &result) != nil || result.Error != nil {
		return nil, fmt.Errorf("guest diagnostic rejected")
	}
	return result.Return, nil
}

func diagnosticText(err error) string {
	msg := err.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return msg
}

// nextRecovery keeps a failed guest probe distinct from lost credentials.
// needsBootstrap comes only from a missing server record whose join token expired.
func nextRecovery(agentPresent, needsBootstrap bool, state, generation, secretGeneration, attempts string, probeErr error) (bool, bool, error) {
	if probeErr != nil && !needsBootstrap {
		return false, false, fmt.Errorf("guest identity probe failed: %s", probeErr.Error())
	}
	if agentPresent && probeErr == nil && state == "present" && generation == secretGeneration && attempts != "" {
		return true, false, nil
	}
	missing := probeErr == nil && state == "missing" && generation == secretGeneration
	if !needsBootstrap && !missing {
		return false, false, nil
	}
	return false, true, nil
}

func (c *controller) guestState(ctx context.Context, vm *unstructured.Unstructured) (string, string, error) {
	ns, name := vm.GetNamespace(), vm.GetName()
	pods, err := c.k.CoreV1().Pods(ns).List(ctx, meta.ListOptions{LabelSelector: "vm.kubevirt.io/name=" + name})
	if err != nil {
		return "", "", err
	}
	var failure error
	for _, pod := range pods.Items {
		if pod.Status.Phase != core.PodRunning || pod.DeletionTimestamp != nil {
			continue
		}
		domain := ns + "_" + name
		r, e := c.qga(ctx, ns, pod.Name, domain, map[string]interface{}{"execute": "guest-exec", "arguments": map[string]interface{}{"path": "/usr/libexec/saw-identity-status", "capture-output": true}})
		if e != nil {
			failure = e
			continue
		}
		pid, ok := r["pid"]
		if !ok {
			failure = fmt.Errorf("guest diagnostic rejected")
			continue
		}
		var pending error
		for i := 0; i < 10; i++ {
			r, e = c.qga(ctx, ns, pod.Name, domain, map[string]interface{}{"execute": "guest-exec-status", "arguments": map[string]interface{}{"pid": pid}})
			if e != nil {
				return "", "", e
			}
			if done, _ := r["exited"].(bool); done {
				if code, _ := r["exitcode"].(float64); code != 0 {
					return "", "", fmt.Errorf("guest identity diagnostic not installed")
				}
				encoded, _ := r["out-data"].(string)
				decoded, e := base64.StdEncoding.DecodeString(encoded)
				if e != nil {
					return "", "", e
				}
				var state struct {
					State      string `json:"state"`
					Generation string `json:"generation"`
				}
				if json.Unmarshal(decoded, &state) != nil {
					return "", "", fmt.Errorf("invalid guest identity status")
				}
				return state.State, state.Generation, nil
			}
			pending = fmt.Errorf("guest identity diagnostic timed out")
			select {
			case <-ctx.Done():
				return "", "", ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		}
		failure = pending
	}
	if failure != nil {
		return "", "", failure
	}
	return "", "", fmt.Errorf("guest diagnostics unavailable")
}

func (c *controller) recover(ctx context.Context, vm *unstructured.Unstructured, s *core.Secret) error {
	ns, name := vm.GetNamespace(), vm.GetName()
	vmi, err := c.d.Resource(schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances"}).Namespace(ns).Get(ctx, name, meta.GetOptions{})
	if kerrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if s.Annotations["saw.redhat.com/restart-pending"] == "true" {
		// Persist the VMI UID before requesting the restart; after interruption,
		// the new VMI proves the operation completed, without restarting it again.
		old := s.Annotations["saw.redhat.com/restart-vmi"]
		if old != "" && old != string(vmi.GetUID()) {
			delete(s.Annotations, "saw.redhat.com/restart-pending")
			delete(s.Annotations, "saw.redhat.com/restart-vmi")
			_, err = c.k.CoreV1().Secrets(ns).Update(ctx, s, meta.UpdateOptions{})
			return err
		}
		if old == "" {
			s.Annotations["saw.redhat.com/restart-vmi"] = string(vmi.GetUID())
			_, err = c.k.CoreV1().Secrets(ns).Update(ctx, s, meta.UpdateOptions{})
			if err != nil {
				return err
			}
		}
		// KubeVirt coalesces repeated restart requests while the same VMI exits.
		_, err = c.k.CoreV1().RESTClient().Put().AbsPath("/apis/subresources.kubevirt.io/v1/namespaces/" + ns + "/virtualmachines/" + name + "/restart").Body([]byte(`{}`)).DoRaw(ctx)
		return err
	}
	agent, err := c.agents.GetAgent(ctx, &agentv1.GetAgentRequest{Id: id(c.td, string(s.Data["node-path"]))})
	if err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	expires, _ := strconv.ParseInt(string(s.Data["expires"]), 10, 64)
	needsBootstrap := status.Code(err) == codes.NotFound && time.Now().Unix() > expires
	state, generation, probeErr := c.guestState(ctx, vm)
	if probeErr != nil && needsBootstrap {
		log.Printf("identity probe %s/%s failed: %s", ns, name, probeErr)
	}
	clear, reenroll, decisionErr := nextRecovery(agent != nil, needsBootstrap, state, generation, string(s.Data["generation"]), s.Annotations["saw.redhat.com/recovery-attempts"], probeErr)
	if decisionErr != nil {
		return decisionErr
	}
	if clear {
		delete(s.Annotations, "saw.redhat.com/recovery-attempts")
		_, err = c.k.CoreV1().Secrets(ns).Update(ctx, s, meta.UpdateOptions{})
		return err
	}
	// A server outage or guest probe failure never proves credential loss.
	if !reenroll {
		return nil
	}
	if agent != nil {
		if err = c.revoke(ctx, s); err != nil {
			return err
		}
	}
	_, err = c.bootstrap(ctx, vm, s)
	return err
}
