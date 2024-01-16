// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"encoding/json"
	"fmt"
	"strings"
)

type (
	Relation struct {
		Name              string             `json:"name"`
		Types             []RelationType     `json:"types,omitempty"`
		SubjectSetRewrite *SubjectSetRewrite `json:"rewrite,omitempty"`
	}

	RelationType struct {
		// relationType type unions will have Namespace and Relation populated
		Namespace string `json:"namespace"`
		Relation  string `json:"relation,omitempty"` // optional

		// relationType type intersections will be modeled in Types
		Types []RelationType `json:"types,omitempty"`
	}
	RelationTypes []RelationType

	// TraversedType represents the type being traversed. for example:
	// In `this.related.some_relation.traverse((x) => ...)`, the relation `some_relation` would have an
	// arbitrary `type`. This type could be simple (Foo), a type union (Foo | Bar), or a type intersection (Foo & Bar)
	// TraversalType captures both the namespace this relation is being accessed (the namespace of `this` in the example
	// above) and the RelationTypes values of the relation
	TraversedType struct {
		Namespace string        `json:"namespace"`
		Types     RelationTypes `json:"types,omitempty"`
	}

	SubjectSetRewrite struct {
		Operation Operator `json:"operator"`
		Children  Children `json:"children"`
	}

	Children []Child

	// Child are all possible types of subject-set rewrites.
	Child interface {
		// AsRewrite returns the child as a subject-set rewrite, as relations
		// require a top-level rewrite, even if just one child was parsed.
		AsRewrite() *SubjectSetRewrite
	}

	SubjectEqualsObject struct {
		TraversedTypes []TraversedType `json:"types"`
	}

	ComputedSubjectSet struct {
		Relation string `json:"relation"`
	}

	TupleToSubjectSet struct {
		TraversedTypes             []TraversedType    `json:"traversed_types,omitempty"`
		Relation                   string             `json:"relation"`
		ComputedSubjectSetRelation *SubjectSetRewrite `json:"computed_subject_set_relation"`
	}

	// InvertResult inverts the check result of the child.
	InvertResult struct {
		Child Child `json:"inverted"`
	}
)

type Operator int

//go:generate stringer -type=Operator -linecomment
const (
	OperatorOr  Operator = iota // or
	OperatorAnd                 // and
)

type RelationKind int

//go:generate stringer -type=RelationKind -linecomment
const (
	TypeSimple RelationKind = iota
	TypeUnion
	TypeIntersection
)

func (rt RelationType) String() string {
	var res string
	switch {
	case len(rt.Types) == 0 && len(rt.Relation) == 0:
		res = rt.Namespace
	case len(rt.Types) == 0:
		res = fmt.Sprintf("SubjectSet<%s,%s>", rt.Namespace, rt.Relation)
	default:
		resarr := make([]string, 0)
		for _, t := range rt.Types {
			resarr = append(resarr, t.String())
		}
		res = strings.Join(resarr, " & ")
	}

	return res
}

func (rts RelationTypes) String() string {
	res := rts.Kind().String()
	ltypes := len(rts)
	if rts.Kind() == TypeSimple {
		if ltypes > 0 {
			return fmt.Sprintf("%s: %s", res, rts[0].Namespace)
		}
	}
	types := make([]string, 0)

	for _, t := range rts {
		types = append(types, t.String())
	}
	res = fmt.Sprintf("%s: %s", res, strings.Join(types, " | "))
	if ltypes > 0 {
		res = fmt.Sprintf("(%s)", res)
	}

	return res
}

func (rts RelationTypes) Kind() (kind RelationKind) {
	switch {
	case rts.IsTypeSimple():
		kind = TypeSimple
	case rts.IsTypeUnion():
		kind = TypeUnion
	case rts.IsTypeIntersection():
		kind = TypeIntersection
	default:
		panic("inconceivable kind")
	}
	return
}

// IsTypeIntersection does thie RelationTypes represent a TypeIntersection
// (i.e., is the relation described as an array of an intersection type: Foo & Bar)
func (rts RelationTypes) IsTypeIntersection() bool {
	if len(rts) == 0 {
		return false
	}

	for _, rt := range rts {
		if rt.IsTypeIntersection() {
			return true
		}
	}

	return false
}

// IsTypeUnion does thie RelationTypes represent a TypeUnion
// (i.e., is the relation described as an array of a union type: Foo | Bar)
// Note that a TypeSimple is a TypeUnion but a TypeUnion is not necessarily a TypeSimple
func (rts RelationTypes) IsTypeUnion() bool {
	if len(rts) == 0 {
		return true
	}

	for _, rt := range rts {
		if rt.IsTypeIntersection() {
			return false
		}
	}

	return true
}

// IsTypeSimple does thie RelationTypes represent a TypeSimple
// (i.e., is the relation described as an array of a single type: Foo)
// Note that a TypeSimple is a TypeUnion but a TypeUnion is not necessarily a TypeSimple
func (rts RelationTypes) IsTypeSimple() bool {
	if len(rts) == 1 && rts[0].IsTypeSimple() {
		return true
	}

	return false
}

// IsTypeIntersection Type intersections with values in Relation would be considered SubjectSets. For example: `users: (User & SubjectSet<Group, "members">)[]
func (rt RelationType) IsTypeIntersection() bool {
	return len(rt.Namespace) == 0 && len(rt.Types) != 0
}

func (rt RelationType) IsTypeSimple() bool {
	return len(rt.Namespace) > 0 && len(rt.Types) == 0
}

func (re Relation) String() string {
	res := fmt.Sprintf("[%s]:", re.Name)
	ltypes := len(re.Types)
	if re.Kind() == TypeSimple {
		if ltypes > 0 {
			return fmt.Sprintf("%s:%s", res, re.Types[0].Namespace)
		}
	}
	types := make([]string, 0)

	for _, t := range re.Types {
		types = append(types, t.String())
	}
	res = fmt.Sprintf("%s:%s", res, strings.Join(types, " | "))
	if ltypes > 0 {
		res = fmt.Sprintf("(%s)", res)
	}

	return res
}

// IsTypeIntersection Type intersections with values in Relation would be considered SubjectSets. For example: `users: (User & SubjectSet<Group, "members">)[]
func (re Relation) IsTypeIntersection() bool {
	if len(re.Types) < 1 {
		return false
	}
	for _, t := range re.Types {
		if t.IsTypeIntersection() {
			return true
		}
	}
	return false
}

func (re Relation) Kind() RelationKind {
	if len(re.Types) == 0 || (len(re.Types) == 1 && !re.Types[0].IsTypeIntersection()) {
		return TypeSimple
	}
	if re.IsTypeIntersection() {
		return TypeIntersection
	}

	return TypeUnion
}

func (i Operator) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.String())
}

func (r *SubjectSetRewrite) AsRewrite() *SubjectSetRewrite { return r }
func (c *ComputedSubjectSet) AsRewrite() *SubjectSetRewrite {
	return &SubjectSetRewrite{Children: []Child{c}}
}
func (t *TupleToSubjectSet) AsRewrite() *SubjectSetRewrite {
	return &SubjectSetRewrite{Children: []Child{t}}
}
func (i *InvertResult) AsRewrite() *SubjectSetRewrite {
	return &SubjectSetRewrite{Children: []Child{i}}
}
func (e *SubjectEqualsObject) AsRewrite() *SubjectSetRewrite {
	return &SubjectSetRewrite{Children: []Child{e}}
}
