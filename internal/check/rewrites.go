// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"context"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"

	"github.com/ory/keto/internal/check/checkgroup"
	"github.com/ory/keto/internal/namespace/ast"
	"github.com/ory/keto/internal/relationtuple"
	"github.com/ory/keto/internal/x"
	"github.com/ory/keto/ketoapi"
)

func checkNotImplemented(_ context.Context, resultCh chan<- checkgroup.Result) {
	resultCh <- checkgroup.Result{Err: errors.WithStack(errors.New("not implemented"))}
}

func toTreeNodeType(op ast.Operator) ketoapi.TreeNodeType {
	switch op {
	case ast.OperatorOr:
		return ketoapi.TreeNodeUnion
	case ast.OperatorAnd:
		return ketoapi.TreeNodeIntersection
	default:
		return ketoapi.TreeNodeUnion
	}
}

func (e *Engine) checkSubjectSetRewrite(
	ctx context.Context,
	tuple *relationTuple,
	rewrite *ast.SubjectSetRewrite,
	restDepth int,
) checkgroup.CheckFunc {
	if restDepth <= 0 {
		e.d.Logger().Debug("reached max-depth, therefore this query will not be further expanded")
		return checkgroup.UnknownMemberFunc
	}

	e.d.Logger().
		WithField("request", tuple.String()).
		Trace("check subject-set rewrite")

	var (
		op      binaryOperator
		checks  []checkgroup.CheckFunc
		handled = make(map[int]struct{})
	)
	switch rewrite.Operation {
	case ast.OperatorOr:
		op = or
	case ast.OperatorAnd:
		op = and
	default:
		return checkNotImplemented
	}

	// Shortcut for ORs of ComputedSubjectSets
	if rewrite.Operation == ast.OperatorOr {
		var computedSubjectSets []string
		for i, child := range rewrite.Children {
			switch c := child.(type) {
			case *ast.ComputedSubjectSet:
				handled[i] = struct{}{}
				computedSubjectSets = append(computedSubjectSets, c.Relation)
			}
		}
		if len(computedSubjectSets) > 0 {
			checks = append(checks, func(ctx context.Context, resultCh chan<- checkgroup.Result) {
				res, err := e.d.Traverser().TraverseSubjectSetRewrite(ctx, tuple, computedSubjectSets)
				if err != nil {
					resultCh <- checkgroup.Result{Err: errors.WithStack(err)}
					return
				}
				g := checkgroup.New(ctx)
				defer func() { resultCh <- g.Result() }()
				for _, result := range res {
					if result.Found {
						g.SetIsMember()
						return
					}
				}
				// If not, we must go another hop:
				for _, result := range res {
					g.Add(e.checkIsAllowed(ctx, result.To, restDepth-1, true))
				}
			})
		}
	}

	for i, child := range rewrite.Children {
		if _, found := handled[i]; found {
			continue
		}

		switch c := child.(type) {

		case *ast.TupleToSubjectSet:
			checks = append(checks, checkgroup.WithEdge(checkgroup.Edge{
				Tuple: *tuple,
				Type:  ketoapi.TreeNodeTupleToSubjectSet,
			}, e.checkTupleToSubjectSet(tuple, c, restDepth)))

		case *ast.ComputedSubjectSet:
			checks = append(checks, checkgroup.WithEdge(checkgroup.Edge{
				Tuple: *tuple,
				Type:  ketoapi.TreeNodeComputedSubjectSet,
			}, e.checkComputedSubjectSet(ctx, tuple, c, restDepth)))

		case *ast.SubjectSetRewrite:
			checks = append(checks, checkgroup.WithEdge(checkgroup.Edge{
				Tuple: *tuple,
				Type:  toTreeNodeType(c.Operation),
			}, e.checkSubjectSetRewrite(ctx, tuple, c, restDepth-1)))

		case *ast.InvertResult:
			checks = append(checks, checkgroup.WithEdge(checkgroup.Edge{
				Tuple: *tuple,
				Type:  ketoapi.TreeNodeNot,
			}, e.checkInverted(ctx, tuple, c, restDepth)))

		case *ast.SubjectEqualsObject:
			checks = append(checks, checkgroup.WithEdge(checkgroup.Edge{
				Tuple: *tuple,
				Type:  ketoapi.TreeNodeSubjectEqObject,
			}, e.checkSubjectEqualsObject(ctx, tuple, c, restDepth)))

		default:
			return checkNotImplemented
		}
	}

	return func(ctx context.Context, resultCh chan<- checkgroup.Result) {
		resultCh <- op(ctx, checks)
	}
}

func (e *Engine) checkInverted(
	ctx context.Context,
	tuple *relationTuple,
	inverted *ast.InvertResult,
	restDepth int,
) checkgroup.CheckFunc {
	if restDepth < 0 {
		e.d.Logger().Debug("reached max-depth, therefore this query will not be further expanded")
		return checkgroup.UnknownMemberFunc
	}

	e.d.Logger().
		WithField("request", tuple.String()).
		Trace("invert check")

	var check checkgroup.CheckFunc

	switch c := inverted.Child.(type) {

	case *ast.TupleToSubjectSet:
		check = checkgroup.WithEdge(checkgroup.Edge{
			Tuple: *tuple,
			Type:  ketoapi.TreeNodeTupleToSubjectSet,
		}, e.checkTupleToSubjectSet(tuple, c, restDepth))

	case *ast.ComputedSubjectSet:
		check = checkgroup.WithEdge(checkgroup.Edge{
			Tuple: *tuple,
			Type:  ketoapi.TreeNodeComputedSubjectSet,
		}, e.checkComputedSubjectSet(ctx, tuple, c, restDepth))

	case *ast.SubjectSetRewrite:
		check = checkgroup.WithEdge(checkgroup.Edge{
			Tuple: *tuple,
			Type:  toTreeNodeType(c.Operation),
		}, e.checkSubjectSetRewrite(ctx, tuple, c, restDepth))

	case *ast.InvertResult:
		check = checkgroup.WithEdge(checkgroup.Edge{
			Tuple: *tuple,
			Type:  ketoapi.TreeNodeNot,
		}, e.checkInverted(ctx, tuple, c, restDepth))
	case *ast.SubjectEqualsObject:
		check = checkgroup.WithEdge(checkgroup.Edge{
			Tuple: *tuple,
			Type:  ketoapi.TreeNodeSubjectEqObject,
		}, e.checkSubjectEqualsObject(ctx, tuple, c, restDepth))

	default:
		return checkNotImplemented
	}

	return func(ctx context.Context, resultCh chan<- checkgroup.Result) {
		innerCh := make(chan checkgroup.Result)
		go check(ctx, innerCh)
		select {
		case result := <-innerCh:
			// invert result here
			switch result.Membership {
			case checkgroup.IsMember:
				result.Membership = checkgroup.NotMember
			case checkgroup.NotMember:
				result.Membership = checkgroup.IsMember
			}
			resultCh <- result
		case <-ctx.Done():
			resultCh <- checkgroup.Result{Err: errors.WithStack(ctx.Err())}
		}
	}
}

// checkSubjectEqualsObject verifies that, for a given tuple, the subject and object are the same.
//
// Checks that the subject and object refer to the same entity. The check
// is performed by creating a subject from the object based on what the tuple subject type is.
// If the tuple subject is a SubjectSet, the tuple's Namespace is used with the object. If the
// tuple subject is a SubjectID, the object's ID is used as a SubjectID.
// The object-subject and tuple subject are compared using Subject.Equals. This was added to support
// `this == ctx.subject` for identity permission cases. See https://github.com/ory/keto/issues/1204
func (e *Engine) checkSubjectEqualsObject(
	_ context.Context,
	r *relationTuple,
	subjectSet *ast.SubjectEqualsObject,
	restDepth int,
) checkgroup.CheckFunc {
	if restDepth < 0 {
		e.d.Logger().Debug("reached max-depth, therefore this query will not be further expanded")
		return checkgroup.UnknownMemberFunc
	}

	e.d.Logger().
		WithField("request", r.String()).
		Trace("check subject equals object")

	return func(ctx context.Context, resultCh chan<- checkgroup.Result) {
		g := checkgroup.New(ctx)
		var objAsSubj relationtuple.Subject
		types := subjectSet.TraversedTypes
		if len(types) == 0 {
			types = []ast.TraversedType{{Namespace: r.Namespace}}
		}
		checks := make([]checkgroup.CheckFunc, 0)
		for _, sstt := range types {
			rtypes := sstt.Types
			if len(rtypes) == 0 {
				rtypes = ast.RelationTypes{{Namespace: sstt.Namespace}}
			}
			for _, ssrt := range rtypes {
				switch r.Subject.(type) {
				case *relationtuple.SubjectSet:
					objAsSubj = &relationtuple.SubjectSet{
						Namespace: ssrt.Namespace,
						Object:    r.Object,
					}
					if r.Subject.Equals(objAsSubj) {
						checks = append(checks, checkgroup.IsMemberFunc)
					} else {
						checks = append(checks, checkgroup.NotMemberFunc)
					}
				case *relationtuple.SubjectID:
					objAsSubj = &relationtuple.SubjectID{
						ID: r.Object,
					}
					if r.Subject.Equals(objAsSubj) {
						checks = append(checks, checkgroup.IsMemberFunc)
					} else {
						checks = append(checks, checkgroup.NotMemberFunc)
					}
				default:
					checks = append(checks, checkgroup.UnknownMemberFunc)
				}
			}
		}
		g.Add(func(ctx context.Context, resultCh chan<- checkgroup.Result) {
			resultCh <- or(ctx, checks)
		})

		resultCh <- g.Result()
	}
}

// checkComputedSubjectSet rewrites the relation tuple to use the subject-set relation
// instead of the relation from the tuple.
//
// A relation tuple n:obj#original_rel@user is rewritten to
// n:obj#subject-set@user, where the 'subject-set' relation is taken from the
// subjectSet.Relation.
func (e *Engine) checkComputedSubjectSet(
	ctx context.Context,
	r *relationTuple,
	subjectSet *ast.ComputedSubjectSet,
	restDepth int,
) checkgroup.CheckFunc {
	if restDepth < 0 {
		e.d.Logger().Debug("reached max-depth, therefore this query will not be further expanded")
		return checkgroup.UnknownMemberFunc
	}

	e.d.Logger().
		WithField("request", r.String()).
		WithField("computed subjectSet relation", subjectSet.Relation).
		Trace("check computed subjectSet")

	return e.checkIsAllowed(ctx, &relationTuple{
		Namespace: r.Namespace,
		Object:    r.Object,
		Relation:  subjectSet.Relation,
		Subject:   r.Subject,
	}, restDepth, false)
}

// checkTupleToSubjectSet rewrites the relation tuple to use the subject-set relation.
//
// Given a relation tuple like docs:readme#editor@user, and a tuple-to-subject-set
// rewrite with the relation "parent" and the computed subject-set relation
// "owner", the following checks will be performed:
//
//   - query for all tuples like docs:readme#parent@??? to get a list of subjects
//     that have the parent relation on docs:readme
//
// * For each matching subject, then check if subject#owner@user.
func (e *Engine) checkTupleToSubjectSet(
	tuple *relationTuple,
	subjectSet *ast.TupleToSubjectSet,
	restDepth int,
) checkgroup.CheckFunc {
	if restDepth < 0 {
		e.d.Logger().Debug("reached max-depth, therefore this query will not be further expanded")
		return checkgroup.UnknownMemberFunc
	}

	e.d.Logger().
		WithField("request", tuple.String()).
		WithField("tuple to subject-set relation", subjectSet.Relation).
		WithField("tuple to subject-set computed", subjectSet.ComputedSubjectSetRelation).
		Trace("check tuple to subjectSet")

	return func(ctx context.Context, resultCh chan<- checkgroup.Result) {
		var (
			prevPage, nextPage string
			tuples             []*relationTuple
			err                error
			qObj               uuid.UUID
			ok                 bool
			subSet             *relationtuple.SubjectSet
		)
		g := checkgroup.New(ctx)
		for nextPage = "x"; nextPage != "" && !g.Done(); prevPage = nextPage {
			tuples, nextPage, err = e.d.RelationTupleManager().GetRelationTuples(
				ctx,
				&query{
					Namespace: &tuple.Namespace,
					Object:    &tuple.Object,
					Relation:  &subjectSet.Relation,
				},
				x.WithToken(prevPage))
			if err != nil {
				g.Add(checkgroup.ErrorFunc(err))
				return
			}

			for _, t := range tuples {
				e.d.Logger().
					WithField("query tuple", t.String()).
					Trace("check tuple to subjectSet(tuples)")

				if subSet, ok = t.Subject.(*relationtuple.SubjectSet); ok {
					qObj = subSet.Object
				} else {
					qObj = t.Subject.(*relationtuple.SubjectID).UniqueID()
				}
				checks := e.createTupleChildrenChecks(ctx, subjectSet, tuple, qObj, restDepth)
				g.Add(func(ctx context.Context, resultCh chan<- checkgroup.Result) {
					resultCh <- or(ctx, checks)
				})
			}
		}

		resultCh <- g.Result()
	}
}

func (e *Engine) createTupleChildrenChecks(ctx context.Context, subjectSet *ast.TupleToSubjectSet, tuple *relationTuple, qObj uuid.UUID, restDepth int) (checks []checkgroup.CheckFunc) {
	checks = make([]checkgroup.CheckFunc, 0)

	for _, tc := range subjectSet.ComputedSubjectSetRelation.Children {
		for _, traversedTypes := range subjectSet.TraversedTypes {
			for _, typeUnion := range traversedTypes.Types {
				var resolvedType = []ast.RelationType{typeUnion}
				if typeUnion.IsTypeIntersection() {
					resolvedType = typeUnion.Types
				}
				for _, combinedType := range resolvedType {
					switch tcc := tc.(type) {
					case *ast.ComputedSubjectSet:
						checks = append(checks, e.checkIsAllowed(ctx, &relationTuple{
							Namespace: combinedType.Namespace,
							Object:    qObj,
							Relation:  tcc.Relation,
							Subject:   tuple.Subject,
						}, restDepth-1, false))
					case *ast.TupleToSubjectSet:
						checks = append(checks, e.checkTupleToSubjectSet(&relationTuple{
							Namespace: combinedType.Namespace,
							Object:    qObj,
							Relation:  tcc.Relation,
							Subject:   tuple.Subject,
						}, tc.(*ast.TupleToSubjectSet), restDepth-1))
					case *ast.SubjectEqualsObject:
						checks = append(checks, e.checkSubjectEqualsObject(ctx, &relationTuple{
							Namespace: combinedType.Namespace,
							Object:    qObj,
							Subject:   tuple.Subject,
						}, tc.(*ast.SubjectEqualsObject), restDepth-1))
					case *ast.SubjectSetRewrite:
						checks = append(checks, e.checkSubjectSetRewrite(ctx, &relationTuple{
							Namespace: combinedType.Namespace,
							Object:    qObj,
							Relation:  subjectSet.Relation,
							Subject:   tuple.Subject,
						}, tc.(*ast.SubjectSetRewrite), restDepth-1))
					default:
						panic("really can't happen")
					}
				}
			}
		}
	}

	return checks
}
