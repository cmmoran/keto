// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"github.com/ory/keto/internal/namespace/ast"
)

type (
	namespaceQuery []namespace
	relationQuery  []ast.Relation
	typeCheck      func(p *parser)
)

func (ns namespaceQuery) namespaces() []string {
	res := make([]string, 0)
	for _, t := range ns {
		res = append(res, t.Name)
	}

	return res
}

func (p *parser) query() namespaceQuery {
	return p.namespaces
}

func (ns namespaceQuery) find(name string) (*namespace, bool) {
	for _, n := range ns {
		if n.Name == name {
			return &n, true
		}
	}
	return nil, false
}

func (ns namespaceQuery) findRelation(namespace, relation string) (*ast.Relation, bool) {
	n, ok := ns.find(namespace)
	if !ok {
		return nil, false
	}
	return relationQuery(n.Relations).find(relation)
}

func (rs relationQuery) find(name string) (*ast.Relation, bool) {
	for _, r := range rs {
		if r.Name == name {
			return &r, true
		}
	}
	return nil, false
}

func (p *parser) typeCheck() {
	for _, check := range p.checks {
		check(p)
	}
}

func (p *parser) addCheck(check typeCheck) {
	p.checks = append(p.checks, check)
}

// checkNamespace checks that the there exists a namespace with the given name.
func checkNamespaceExists(namespace item) typeCheck {
	return func(p *parser) {
		if _, ok := namespaceQuery(p.namespaces).find(namespace.Val); ok {
			return
		}
		p.addErr(namespace, "namespace %q was not declared", namespace.Val)
	}
}

// checkNamespaceHasRelation checks that 1. there exists the given namespace,
// and 2. that there exists the given relation in that namespace.
func checkNamespaceHasRelation(namespace, relation item) typeCheck {
	return func(p *parser) {
		if n, ok := namespaceQuery(p.namespaces).find(namespace.Val); ok {
			if _, ok := relationQuery(n.Relations).find(relation.Val); ok {
				return
			}
			p.addErr(relation,
				"namespace %q did not declare relation %q",
				namespace.Val, relation.Val)
			return
		}
		p.addErr(namespace, "namespace %q was not declared", namespace.Val)
	}
}

// checkCurrentNamespaceHasRelation checks that the give relation exists in the
// current namespace.
func checkCurrentNamespaceHasRelation(current *namespace, relation item) typeCheck {
	namespace := current.Name
	return func(p *parser) {
		if n, ok := namespaceQuery(p.namespaces).find(namespace); ok {
			if _, ok := relationQuery(n.Relations).find(relation.Val); ok {
				return
			}
			p.addErr(relation,
				"namespace %q did not declare relation %q",
				namespace, relation.Val)
			return
		}
		p.addErr(relation, "namespace %q was not declared", namespace)
	}
}

// checkArbitraryNamespaceHasRelation checks that the given relation exists in the
// given namespaces.
func checkNamespacesHavesRelation(namespacePtr *namespace, namespaces []namespace, relation item) typeCheck {
	if len(namespaces) == 0 {
		namespaces = []namespace{
			*namespacePtr,
		}
	}

	return func(p *parser) {
		for _, ns := range namespaces {
			if _, ok := relationQuery(ns.Relations).find(relation.Val); ok {
				return
			}
			p.addErr(relation,
				"namespace %q did not declare relation %q",
				ns.Name, relation.Val)
			return
		}
	}
}

func checkNamespacesHaveRelationTypeAndRelation(namespacePtr *namespace, namespaces []namespace, relationType item, relation string) typeCheck {
	if len(namespaces) == 0 {
		namespaces = []namespace{
			*namespacePtr,
		}
	}

	return func(p *parser) {
		for _, ns := range namespaces {
			recursiveCheckAllRelationsTypesHaveRelation(p, relationType, ns.Name, relationType.Val, relation, tupleToSubjectSetTypeCheckMaxDepth)
		}
	}
}

func recursiveCheckAllRelationsTypesHaveRelation(p *parser, item item, namespace string, relationType string, relation string, depth int) {
	if depth < 0 {
		p.addErr(item, "could not typecheck deeply nested SubjectSet further")
		return
	}
	r, ok := namespaceQuery(p.namespaces).findRelation(namespace, relationType)
	if !ok {
		p.addErr(item, "relation %q was not declared in namespace %q",
			relationType, namespace)
		return
	}
	for _, t := range r.Types {
		if t.Relation == "" {
			if _, ok := p.query().findRelation(t.Namespace, relation); !ok {
				p.addErr(item, "relation %q was not declared in namespace %q",
					relation, t.Namespace)
			}
		} else {
			// Type is a subject set, we need to recursively check if the type has
			// the required relation.
			recursiveCheckAllRelationsTypesHaveRelation(
				p, item, t.Namespace, t.Relation, relation, depth-1)
		}
	}
}
