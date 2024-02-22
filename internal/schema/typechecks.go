// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"fmt"
	"strings"

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

func (rs relationQuery) String() string {
	results := make([]string, 0)
	for _, r := range rs {
		results = append(results, r.String())
	}

	return fmt.Sprintf("[%s]", strings.Join(results, ","))
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
			if _, rok := relationQuery(n.Relations).find(relation.Val); rok {
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

// checkIdentifierTypesHaveRelation checks that the given relation exists in the
// given namespaces.
func checkIdentifierTypesHaveRelation(namespacePtr *namespace, identifiers []ast.TraversedType, relation item) typeCheck {
	currentNs := namespacePtr.Name

	return func(p *parser) {
		if len(identifiers) == 0 {
			if rel, ok := namespaceQuery(p.namespaces).findRelation(currentNs, relation.Val); ok {
				identifiers = []ast.TraversedType{{
					Namespace: currentNs,
					Types:     rel.Types,
				}}
			}
		}
		for _, ns := range identifiers {
			// unions all
			for _, nst := range ns.Types {
				if nst.IsTypeIntersection() {
					// for intersection types, we only need one member of the intersection to have the relation
					found := false
					for _, nstt := range nst.Types {
						if _, ok := namespaceQuery(p.namespaces).findRelation(nstt.Namespace, relation.Val); ok {
							found = true
						}
					}
					if !found {
						p.addErr(relation,
							"From [%q], %q did not properly declare relation %q",
							ns.Namespace, ns.Types.String(), relation.Val)
					}
				} else if len(nst.Namespace) > 0 {
					// for union types, we need all members of the union to have the relation
					if _, ok := namespaceQuery(p.namespaces).findRelation(nst.Namespace, relation.Val); !ok {
						p.addErr(relation,
							"From %q, %q did not properly declare relation %q",
							ns.Namespace, ns.Types.String(), relation.Val)
						//p.addErr(relation,
						//	"%q (%q) did not declare relation %q",
						//	nst.Namespace, ns.Types, relation.Val)
					}
				} else {
					panic("how did we get here?")
				}
			}
		}
	}
}

func checkNamespacesHaveRelationTypeAndRelation(namespacePtr *namespace, identifiers []ast.Relation, relationType item, relation string) typeCheck {
	if len(identifiers) == 0 {
		identifiers = namespacePtr.Relations
	}

	return func(p *parser) {
		for _, ns := range identifiers {
			for _, typ := range ns.Types {
				recursiveCheckSomeRelationsTypesHaveRelation(p, relationType, typ, relation, tupleToSubjectSetTypeCheckMaxDepth)
			}
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
func recursiveCheckSomeRelationsTypesHaveRelation(p *parser, item item, r ast.RelationType, relation string, depth int) {
	if depth < 0 {
		p.addErr(item, "could not typecheck deeply nested SubjectSet further")
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
