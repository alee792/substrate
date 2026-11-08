// Copyright 2026 The Agent Substrate Authors
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

package steps

import (
	"context"
	"fmt"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"go.ate.dev/substrate/cmd/ate-setup/internal/config"
	"go.ate.dev/substrate/cmd/ate-setup/internal/kube"
	"go.ate.dev/substrate/cmd/ate-setup/internal/log"
)

// Manifests for the bundled Kubernetes Secrets credential provider. They sit
// outside the ate-install tree because only installs that select the provider
// apply them. sample-secret.yaml in the same directory is never applied.
const (
	k8sCredentialProviderDir            = "manifests/egress-credential-injection"
	k8sCredentialProviderManifest       = "k8s-credential-provider.yaml"
	k8sCredentialProviderPolicyManifest = "namespace-policy.yaml"

	// Object names from the manifests above; credprovider_test.go checks them.
	k8sCredentialProviderDeployment      = "k8s-credential-provider"
	k8sCredentialProviderPolicyConfigMap = "k8s-credential-provider-namespace-policy"
	k8sCredentialProviderSecretReader    = "k8s-credential-provider-secret-reader"
)

// k8sCredentialProviderSecretReaderSelector selects the RoleBindings that
// grant the provider Secret reads in one namespace each.
const k8sCredentialProviderSecretReaderSelector = "app=" + k8sCredentialProviderDeployment

func (e *Env) k8sCredentialProviderPath(manifest string) string {
	return e.Cfg.Path(k8sCredentialProviderDir, manifest)
}

// deployK8sCredentialProvider deploys the bundled provider. The namespace
// policy ConfigMap is applied only when absent: the provider needs it to start,
// but it holds the operator's atespace allow-list, which a redeploy must keep.
//
// Without secretNamespaces, a ClusterRoleBinding lets the provider read
// Secrets in every namespace. With them, a RoleBinding in each listed
// namespace grants the same ClusterRole there, and the ClusterRoleBinding and
// the RoleBindings in namespaces no longer listed are deleted.
func (e *Env) deployK8sCredentialProvider(ctx context.Context, provider config.CredentialProvider) error {
	log.Step("deploy_k8s_credential_provider")
	exists, err := e.Kube.ConfigMapExists(ctx, e.Namespace(), k8sCredentialProviderPolicyConfigMap)
	if err != nil {
		return err
	}
	if !exists {
		if err := e.Kube.ApplyPath(ctx, e.k8sCredentialProviderPath(k8sCredentialProviderPolicyManifest)); err != nil {
			return err
		}
	}
	manifest, err := e.renderResolve(ctx, e.k8sCredentialProviderPath(k8sCredentialProviderManifest))
	if err != nil {
		return err
	}
	objs, err := kube.DecodeManifestBytes(manifest)
	if err != nil {
		return err
	}
	objs, err = k8sCredentialProviderObjects(objs, provider.SecretNamespaces)
	if err != nil {
		return err
	}
	if err := e.Kube.Apply(ctx, objs); err != nil {
		return err
	}
	// The RoleBindings exist by now, so the provider keeps its reads in the
	// listed namespaces while the cluster-wide grant goes away.
	if len(provider.SecretNamespaces) > 0 {
		err := e.Kube.Typed.RbacV1().ClusterRoleBindings().Delete(ctx, k8sCredentialProviderSecretReader, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return e.pruneK8sCredentialProviderRoleBindings(ctx, provider.SecretNamespaces)
}

// k8sCredentialProviderObjects returns the provider's objects with its
// ClusterRoleBinding replaced by a RoleBinding in each of secretNamespaces.
// With none, it returns objs unchanged.
func k8sCredentialProviderObjects(objs []*unstructured.Unstructured, secretNamespaces []string) ([]*unstructured.Unstructured, error) {
	if len(secretNamespaces) == 0 {
		return objs, nil
	}
	var binding *unstructured.Unstructured
	out := make([]*unstructured.Unstructured, 0, len(objs)+len(secretNamespaces))
	for _, obj := range objs {
		if obj.GetKind() == "ClusterRoleBinding" && obj.GetName() == k8sCredentialProviderSecretReader {
			binding = obj
			continue
		}
		out = append(out, obj)
	}
	if binding == nil {
		return nil, fmt.Errorf("provider manifest has no clusterrolebinding/%s", k8sCredentialProviderSecretReader)
	}
	for _, ns := range secretNamespaces {
		rb := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "RoleBinding",
			"metadata": map[string]any{
				"name":      k8sCredentialProviderSecretReader,
				"namespace": ns,
				"labels":    map[string]any{"app": k8sCredentialProviderDeployment},
			},
			"roleRef":  binding.Object["roleRef"],
			"subjects": binding.Object["subjects"],
		}}
		out = append(out, rb.DeepCopy())
	}
	return out, nil
}

// pruneK8sCredentialProviderRoleBindings deletes the provider's RoleBindings
// in namespaces outside keep.
func (e *Env) pruneK8sCredentialProviderRoleBindings(ctx context.Context, keep []string) error {
	rbs, err := e.Kube.Typed.RbacV1().RoleBindings(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		LabelSelector: k8sCredentialProviderSecretReaderSelector,
	})
	if err != nil {
		return err
	}
	for _, rb := range rbs.Items {
		if rb.Name != k8sCredentialProviderSecretReader || slices.Contains(keep, rb.Namespace) {
			continue
		}
		log.Infof("Removing the credential provider's Secret read in namespace %s", rb.Namespace)
		err := e.Kube.Typed.RbacV1().RoleBindings(rb.Namespace).Delete(ctx, rb.Name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// removeK8sCredentialProvider removes a bundled provider left by an earlier
// install, so that it does not keep its Secret reads once the gateway no
// longer uses it.
func (e *Env) removeK8sCredentialProvider(ctx context.Context) error {
	running, err := e.Kube.DeploymentExists(ctx, e.Namespace(), k8sCredentialProviderDeployment)
	if err != nil || !running {
		return err
	}
	log.Step("remove_k8s_credential_provider")
	return e.deleteK8sCredentialProvider(ctx)
}

// deleteK8sCredentialProvider deletes the provider's objects and every
// RoleBinding that grants it Secret reads. The policy ConfigMap stays: it
// holds the operator's allow-list.
func (e *Env) deleteK8sCredentialProvider(ctx context.Context) error {
	if err := e.Kube.DeletePath(ctx, e.k8sCredentialProviderPath(k8sCredentialProviderManifest)); err != nil {
		return err
	}
	return e.pruneK8sCredentialProviderRoleBindings(ctx, nil)
}
