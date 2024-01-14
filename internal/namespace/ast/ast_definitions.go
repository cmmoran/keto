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

	SubjectSetRewrite struct {
		Operation Operator `json:"operator"`
		Children  Children `json:"children"`
	}

	Children = []Child

	// Child are all possible types of subject-set rewrites.
	Child interface {
		// AsRewrite returns the child as a subject-set rewrite, as relations
		// require a top-level rewrite, even if just one child was parsed.
		AsRewrite() *SubjectSetRewrite
	}

	SubjectEqualsObject struct {
		Types []RelationType `json:"types"`
	}

	ComputedSubjectSet struct {
		Relation string `json:"relation"`
	}

	TupleToSubjectSet struct {
		Frames                     []Relation         `json:"-"`
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

// IsTypeIntersection Type intersections with values in Relation would be considered SubjectSets. For example: `users: (User & SubjectSet<Group, "members">)[]
func (rt RelationType) IsTypeIntersection() bool {
	return len(rt.Namespace) == 0 && len(rt.Types) != 0
}

func (rt RelationType) IsTypeSimple() bool {
	return len(rt.Namespace) > 0 && len(rt.Types) == 0
}

func (rt RelationType) Find(typ string) bool {
	if !rt.IsTypeIntersection() {
		return rt.Relation == typ
	} else {
		if len(rt.Types) == 0 {
			return false
		}
		for _, t := range rt.Types {
			if t.Relation == typ {
				return true
			}
		}
	}
	return false
}

func (re Relation) String() string {

	res := ""
	ltypes := len(re.Types)
	if re.Kind() == TypeSimple {
		if ltypes > 0 {
			return re.Types[0].Namespace
		}
	}
	res = ""
	types := make([]string, 0)

	for _, t := range re.Types {
		types = append(types, t.String())
	}
	res = strings.Join(types, " | ")
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
