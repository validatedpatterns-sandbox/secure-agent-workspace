// SAW registrar: one serialized reconciler, workload-authenticated SPIRE API,
// and VM-scoped Kubernetes write permissions. No tenant-supplied entry IDs.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
	core "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

var vmResource = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines"}

const finalizer = "saw.redhat.com/spire-registration"
const opted = "saw.redhat.com/spiffe"

type controller struct {
	k             kubernetes.Interface
	d             dynamic.Interface
	config        *rest.Config
	agents        agentv1.AgentClient
	entries       entryv1.EntryClient
	td, namespace string
	life          lifetimes
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	td := os.Getenv("TRUST_DOMAIN")
	if td == "" {
		log.Fatal("TRUST_DOMAIN is required")
	}
	life, err := lifetimesFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}
	k, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	d, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///spiffe-workload-api/spire-agent.sock")))
	if err != nil {
		log.Fatal("workload identity unavailable")
	}
	defer source.Close()
	tls := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(spiffeid.RequireFromString("spiffe://"+td+"/spire/server")))
	conn, err := grpc.NewClient(env("SPIRE_SERVER", "spire-server.zero-trust-workload-identity-manager.svc:443"), grpc.WithTransportCredentials(credentials.NewTLS(tls)))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	c := &controller{k: k, d: d, config: cfg, agents: agentv1.NewAgentClient(conn), entries: entryv1.NewEntryClient(conn), td: td, namespace: env("POD_NAMESPACE", "zero-trust-workload-identity-manager"), life: life}
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
	defer queue.ShutDown()
	factory := dynamicinformer.NewDynamicSharedInformerFactory(d, 30*time.Second)
	inf := factory.ForResource(vmResource).Informer()
	push := func(obj interface{}) {
		if key, e := cache.DeletionHandlingMetaNamespaceKeyFunc(obj); e == nil {
			queue.Add(key)
		}
	}
	_, err = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{AddFunc: push, UpdateFunc: func(_, new interface{}) { push(new) }, DeleteFunc: push})
	if err != nil {
		log.Fatal(err)
	}
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return
	}
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				queue.ShutDown()
				return
			case <-ticker.C:
				for _, obj := range inf.GetStore().List() {
					push(obj)
				}
			}
		}
	}()
	for {
		key, shutdown := queue.Get()
		if shutdown {
			return
		}
		call, cancel := context.WithTimeout(ctx, 90*time.Second)
		err := c.reconcile(call, key)
		cancel()
		if err != nil {
			log.Printf("reconcile %s failed: %s", key, safeError(err))
			queue.AddRateLimited(key)
		} else {
			queue.Forget(key)
		}
		queue.Done(key)
	}
}

// SPIRE errors can contain join-token agent IDs. Never print their message.
func safeError(err error) string {
	if s, ok := status.FromError(err); ok {
		return "SPIRE " + s.Code().String()
	}
	return err.Error()
}

func has(xs []string, s string) bool {
	for _, v := range xs {
		if v == s {
			return true
		}
	}
	return false
}
func (c *controller) setFinalizer(ctx context.Context, vm *unstructured.Unstructured, add bool) error {
	fs := []string{}
	for _, s := range vm.GetFinalizers() {
		if s != finalizer {
			fs = append(fs, s)
		}
	}
	if add {
		fs = append(fs, finalizer)
	}
	vm.SetFinalizers(fs)
	_, err := c.d.Resource(vmResource).Namespace(vm.GetNamespace()).Update(ctx, vm, meta.UpdateOptions{})
	return err
}

func (c *controller) owned(ctx context.Context, uid string) ([]*types.Entry, error) {
	var out []*types.Entry
	page := ""
	for {
		r, e := c.entries.ListEntries(ctx, &entryv1.ListEntriesRequest{Filter: &entryv1.ListEntriesRequest_Filter{ByHint: wrapperspb.String("saw:" + uid)}, PageToken: page})
		if e != nil {
			return nil, e
		}
		out = append(out, r.Entries...)
		page = r.NextPageToken
		if page == "" {
			return out, nil
		}
	}
}
func (c *controller) deleteEntries(ctx context.Context, entries []*types.Entry) error {
	if len(entries) == 0 {
		return nil
	}
	ids := []string{}
	for _, e := range entries {
		ids = append(ids, e.Id)
	}
	r, err := c.entries.BatchDeleteEntry(ctx, &entryv1.BatchDeleteEntryRequest{Ids: ids})
	if err != nil {
		return err
	}
	for _, r := range r.Results {
		if r.Status.Code != 0 && r.Status.Code != int32(codes.NotFound) {
			return status.Error(codes.Code(r.Status.Code), "delete failed")
		}
	}
	return nil
}
func (c *controller) revoke(ctx context.Context, s *core.Secret) error {
	if s == nil {
		return nil
	}
	node := string(s.Data["node-path"])
	if node == "" {
		return nil
	}
	_, err := c.agents.BanAgent(ctx, &agentv1.BanAgentRequest{Id: id(c.td, node)})
	if status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}

func (c *controller) reconcile(ctx context.Context, key string) error {
	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	vm, err := c.d.Resource(vmResource).Namespace(ns).Get(ctx, name, meta.GetOptions{})
	if kerrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	registered := has(vm.GetFinalizers(), finalizer)
	if vm.GetLabels()[opted] != "true" && !registered {
		return nil
	}
	namespace, err := c.k.CoreV1().Namespaces().Get(ctx, ns, meta.GetOptions{})
	if err != nil {
		return err
	}
	secret, err := c.k.CoreV1().Secrets(ns).Get(ctx, name+"-spire-join-token", meta.GetOptions{})
	if kerrors.IsNotFound(err) {
		secret = nil
	} else if err != nil {
		return err
	}
	uid := string(vm.GetUID())
	if secret != nil && (len(secret.OwnerReferences) != 1 || string(secret.OwnerReferences[0].UID) != uid) {
		return fmt.Errorf("bootstrap Secret belongs to another VM")
	}
	if vm.GetDeletionTimestamp() != nil || vm.GetLabels()[opted] != "true" || namespace.Labels["openshell.pattern/saw"] != "true" {
		if !registered {
			return nil
		}
		old, e := c.owned(ctx, uid)
		if e != nil {
			return e
		}
		if e = c.deleteEntries(ctx, old); e != nil {
			return e
		}
		if e = c.revoke(ctx, secret); e != nil {
			return e
		}
		return c.setFinalizer(ctx, vm, false)
	}
	if !registered {
		return c.setFinalizer(ctx, vm, true)
	}
	ann := vm.GetAnnotations()
	if ann["saw.redhat.com/trust-domain"] != c.td {
		return fmt.Errorf("VM trust domain differs from registrar")
	}
	files := map[string]string{}
	cm, err := c.k.CoreV1().ConfigMaps(ns).Get(ctx, "saw-bom-profiles", meta.GetOptions{})
	if err == nil {
		files = cm.Data
	} else if !kerrors.IsNotFound(err) {
		return err
	}
	// Validate profiles before minting credentials or changing registrations.
	gatewayUID := ann["saw.redhat.com/gateway-uid"]
	if _, err := strconv.ParseUint(gatewayUID, 10, 32); err != nil {
		return fmt.Errorf("gateway UID annotation is required")
	}
	if _, err := desiredEntries(c.td, ns, name, uid, "/validation", files, gatewayUID, c.life.jwtSvid, c.life.x509Svid); err != nil {
		return err
	}
	// An existing join-token Secret keeps its minted expiry. The configured
	// join-token lifetime applies only when this VM has no Secret yet.
	if secret == nil {
		var err error
		secret, err = c.bootstrap(ctx, vm, nil)
		if err != nil {
			return err
		}
	}
	old, err := c.owned(ctx, uid)
	if err != nil {
		return err
	}
	wanted, err := desiredEntries(c.td, ns, name, uid, string(secret.Data["node-path"]), files, gatewayUID, c.life.jwtSvid, c.life.x509Svid)
	if err != nil {
		return err
	}
	byPath := map[string]*types.Entry{}
	for _, e := range old {
		byPath[e.SpiffeId.Path] = e
	}
	for _, want := range wanted {
		got := byPath[want.SpiffeId.Path]
		delete(byPath, want.SpiffeId.Path)
		if got == nil {
			r, e := c.entries.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{Entries: []*types.Entry{want}})
			if e != nil {
				return e
			}
			if len(r.Results) != 1 || r.Results[0].Status.Code != 0 {
				return fmt.Errorf("SPIRE entry creation failed")
			}
		} else {
			// Keep the registration ID. A lifetime change updates that entry
			// in place instead of deleting it and creating another.
			want.Id = got.Id
			want.RevisionNumber = got.RevisionNumber
			want.CreatedAt = got.CreatedAt
			if !proto.Equal(want, got) {
				if want.JwtSvidTtl != got.JwtSvidTtl || want.X509SvidTtl != got.X509SvidTtl {
					log.Printf("update registration %s jwt %d->%d x509 %d->%d", want.SpiffeId.GetPath(), got.JwtSvidTtl, want.JwtSvidTtl, got.X509SvidTtl, want.X509SvidTtl)
				}
				r, e := c.entries.BatchUpdateEntry(ctx, &entryv1.BatchUpdateEntryRequest{Entries: []*types.Entry{want}})
				if e != nil {
					return e
				}
				if len(r.Results) != 1 || r.Results[0].Status.Code != 0 {
					return fmt.Errorf("SPIRE entry update failed")
				}
			}
		}
	}
	stale := []*types.Entry{}
	for _, e := range byPath {
		stale = append(stale, e)
	}
	if err := c.deleteEntries(ctx, stale); err != nil {
		return err
	}
	return c.recover(ctx, vm, secret)
}

func (c *controller) bootstrap(ctx context.Context, vm *unstructured.Unstructured, previous *core.Secret) (*core.Secret, error) {
	generation := 1
	attempts := 0
	if previous != nil {
		generation, _ = strconv.Atoi(string(previous.Data["generation"]))
		generation++
		attempts, _ = strconv.Atoi(previous.Annotations["saw.redhat.com/recovery-attempts"])
		attempts++
		if attempts > 3 {
			return nil, fmt.Errorf("bootstrap retry limit reached; operator investigation required")
		}
	}
	bundle, err := c.k.CoreV1().ConfigMaps(c.namespace).Get(ctx, "spire-bundle", meta.GetOptions{})
	if err != nil {
		return nil, err
	}
	pem := bundle.Data["bundle.crt"]
	if !strings.Contains(pem, "BEGIN CERTIFICATE") {
		return nil, fmt.Errorf("trust bundle is not ready")
	}
	token, err := c.agents.CreateJoinToken(ctx, &agentv1.CreateJoinTokenRequest{Ttl: c.life.joinToken})
	if err != nil {
		return nil, err
	}
	log.Printf("minted join token ttl=%d expires=%d", c.life.joinToken, token.ExpiresAt)
	owner := meta.NewControllerRef(vm, schema.GroupVersionKind{Group: "kubevirt.io", Version: "v1", Kind: "VirtualMachine"})
	s := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: vm.GetName() + "-spire-join-token", Namespace: vm.GetNamespace(), OwnerReferences: []meta.OwnerReference{*owner}}, Data: map[string][]byte{
		"token": []byte(token.Value), "node-path": []byte("/spire/agent/join_token/" + token.Value), "bundle.pem": []byte(pem), "generation": []byte(strconv.Itoa(generation)), "expires": []byte(strconv.FormatInt(token.ExpiresAt, 10)),
	}}
	if previous == nil {
		return c.k.CoreV1().Secrets(vm.GetNamespace()).Create(ctx, s, meta.CreateOptions{})
	}
	s.ResourceVersion = previous.ResourceVersion
	s.Annotations = map[string]string{"saw.redhat.com/restart-pending": "true", "saw.redhat.com/recovery-attempts": strconv.Itoa(attempts)}
	return c.k.CoreV1().Secrets(vm.GetNamespace()).Update(ctx, s, meta.UpdateOptions{})
}
