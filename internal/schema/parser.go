// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"fmt"
	internalNamespace "github.com/ory/keto/internal/namespace"
	"github.com/ory/keto/internal/namespace/ast"
	"slices"
)

type (
	namespace = internalNamespace.Namespace

	parser struct {
		traverseStack []traverseFrame // stack to track traversal context
		lexer         *lexer          // lexer to get tokens from
		namespaces    []namespace     // list of parsed namespaces
		namespace     namespace       // current namespace
		errors        []*ParseError   // errors encountered during parsing
		fatal         bool            // parser encountered a fatal error
		lookahead     *item           // lookahead token
		checks        []typeCheck     // checks to perform on the namespace
	}
	traverseFrame struct {
		traversedTypes []ast.TraversedType
		relation       string
	}
)

func Parse(input string) ([]namespace, []*ParseError) {
	p := &parser{
		lexer:         Lex("input", input),
		traverseStack: make([]traverseFrame, 0),
	}
	return p.parse()
}

func (p *parser) pushFrame(relation item) {
	var current traverseFrame
	if len(p.traverseStack) == 0 {
		// We start in a single namespace traversing into a relation with some arbitrary "types"
		// By the time we're here, the relations have been parsed
		if rels, ok := relationQuery(p.namespace.Relations).find(relation.Val); ok {
			current = traverseFrame{
				traversedTypes: []ast.TraversedType{{
					Namespace: p.namespace.Name,
					Types:     rels.Types,
				}},
				relation: relation.Val,
			}
		}
	} else if len(p.traverseStack) > 0 {
		parent := p.traverseStack[0]
		current = traverseFrame{
			traversedTypes: make([]ast.TraversedType, 0),
			relation:       relation.Val,
		}
		for _, identifier := range parent.traversedTypes {
			for _, typ := range identifier.Types {
				if rels, ok := namespaceQuery(p.namespaces).findRelation(typ.Namespace, relation.Val); ok {
					ntype := ast.TraversedType{
						Namespace: typ.Namespace,
						Types:     rels.Types,
					}
					current.traversedTypes = append(current.traversedTypes, ntype)
				}
			}
		}
	}
	if len(p.traverseStack) > 1 {
		p.traverseStack = append(p.traverseStack[:1], p.traverseStack[0:]...)
		p.traverseStack[0] = current
	} else {
		p.traverseStack = append([]traverseFrame{current}, p.traverseStack...)
	}
}

func (p *parser) popFrame() (*traverseFrame, bool) {
	current := &p.traverseStack[0]
	if len(p.traverseStack) == 1 {
		p.traverseStack = make([]traverseFrame, 0)
	} else if len(p.traverseStack) > 1 {
		p.traverseStack = p.traverseStack[1:]
	}

	return current, current != nil
}

func (p *parser) peekFrame() (*traverseFrame, bool) {
	if len(p.traverseStack) == 0 {
		return nil, false
	}

	return &p.traverseStack[0], true
}

func (p *parser) mark() int64 {
	return p.lexer.mark(p.lookahead)
}

func (p *parser) resetMark() {
	p.lexer.resetMark()
}

func (p *parser) restoreMark() {
	if p.lookahead != nil {
		p.lookahead = nil
	}
	p.lexer.restoreMark()
}

func (p *parser) next() (item item) {
	if p.lookahead != nil {
		item = *p.lookahead
		p.lookahead = nil
	} else {
		return p.lexer.nextNonCommentItem()
	}
	return
}

func (p *parser) peek() item {
	if p.lookahead == nil {
		i := p.lexer.nextNonCommentItem()
		p.lookahead = &i
		return i
	}
	return *p.lookahead
}

func (p *parser) parse() ([]namespace, []*ParseError) {
loop:
	for !p.fatal {
		switch item := p.next(); item.Typ {
		case itemEOF:
			break loop
		case itemError:
			p.addFatal(item, "fatal: %s", item.Val)
		case itemKeywordClass:
			p.parseClass()
		}
	}

	if len(p.errors) == 0 {
		p.typeCheck()
	}

	return p.namespaces, p.errors
}

func (p *parser) addFatal(item item, format string, a ...interface{}) {
	p.addErr(item, format, a...)
	p.fatal = true
}
func (p *parser) addErr(item item, format string, a ...interface{}) {
	err := &ParseError{
		msg:  fmt.Sprintf(format, a...),
		item: item,
		p:    p,
	}
	p.errors = append(p.errors, err)
}

func (p *parser) dump(msg string, args ...interface{}) {
	if p.lookahead == nil {
		p.peek()
	}
	fmt.Printf("Dump %v\n", &ParseError{
		msg:  fmt.Sprintf(msg, args...),
		item: *p.lookahead,
		p:    p,
	})
}

type matcher func(p *parser) (matched bool)

// optional optionally matches the first argument of tokens in the input. If
// matched, the tokens are consumed. If the first token matched, all other
// tokens must match as well.
func optional(tokens ...string) matcher {
	return func(p *parser) bool {
		if len(tokens) == 0 {
			return true
		}
		first := tokens[0]
		if p.peek().Val == first {
			p.next()
			for _, token := range tokens[1:] {
				i := p.next()
				if i.Val != token {
					p.addFatal(i, "expected %q, got %q", token, i.Val)
					return false
				}
			}
		}
		return true
	}
}

// match for the next tokens in the input.
//
// A token is matched depending on the type:
// For string arguments, the input token must match the given string exactly.
// For *string arguments, the input token must be an identifier, and the value
// of the identifier will be written to the *string.
// For *item arguments, the input token will be written to the pointer.
func (p *parser) match(tokens ...interface{}) (matched bool) {
	if p.fatal {
		return false
	}

	for _, token := range tokens {
		switch token := token.(type) {
		case string:
			i := p.next()
			if i.Val != token {
				p.addFatal(i, "expected %q, got %q", token, i.Val)
				return false
			}
		case *string:
			i := p.next()
			if i.Typ != itemIdentifier && i.Typ != itemStringLiteral {
				p.addFatal(i, "expected identifier, got %s", i.Typ)
				return false
			}
			*token = i.Val
		case *item:
			*token = p.next()
		case matcher:
			if !token(p) {
				return false
			}
		default:
			panic(fmt.Sprintf("unexpected token type %T", token))
		}
	}
	return true
}

type itemPredicate func(item) bool

func is(typ itemType) itemPredicate {
	return func(item item) bool {
		return item.Typ == typ
	}
}

func or(typs ...itemType) itemPredicate {
	return func(item item) bool {
		for _, typ := range typs {
			if item.Typ == typ {
				return true
			}
		}
		return false
	}
}

// matchIf matches the tokens iff. the predicate is true.
func (p *parser) matchIf(predicate itemPredicate, tokens ...interface{}) (matched bool) {
	if p.fatal {
		return false
	}
	if !predicate(p.peek()) {
		return false
	}
	return p.match(tokens...)
}

// parseClass parses a class. The "class" token was already consumed.
func (p *parser) parseClass() {
	var name string
	p.match(&name, "implements", "Namespace", "{")
	p.namespace = namespace{Name: name}

	for !p.fatal {
		switch item := p.next(); {
		case item.Typ == itemBraceRight:
			p.namespaces = append(p.namespaces, p.namespace)
			return
		case item.Val == "related":
			p.parseRelated()
		case item.Val == "permits":
			p.parsePermits()
		case item.Typ == itemSemicolon:
			continue
		default:
			p.addFatal(item, "expected 'permits' or 'related', got %q", item.Val)
			return
		}
	}
}

func (p *parser) parseRelated() {
	p.match(":", "{")
	for !p.fatal {
		switch item := p.next(); item.Typ {

		case itemSemicolon:
			continue

		case itemBraceRight:
			return

		case itemIdentifier, itemStringLiteral:
			relation := item.Val
			var types []ast.RelationType
			p.match(":")

			switch item := p.next(); {
			case item.Val == "Array":
				p.match("<")
				types = append(types, p.parseType(itemAngledRight)...)
			case item.Val == "SubjectSet":
				types = append(types, p.matchSubjectSet())
				p.match("[", "]", optional(","))
			case item.Typ == itemParenLeft:
				types = append(types, p.parseType(itemParenRight)...)
				p.match("[", "]", optional(","))
			default:
				types = append(types, ast.RelationType{Namespace: item.Val})
				p.addCheck(checkNamespaceExists(item))
				p.match("[", "]", optional(","))
			}

			p.namespace.Relations = append(p.namespace.Relations, ast.Relation{
				Name:  relation,
				Types: types,
			})

		default:
			p.addFatal(item, "expected identifier or '}', got %s %q", item.Typ.String(), item.Val)
			return
		}
	}
}

func (p *parser) matchSubjectSet() ast.RelationType {
	var namespace, relation item
	p.match("<", &namespace, ",", &relation, ">")
	p.addCheck(checkNamespaceHasRelation(namespace, relation))
	return ast.RelationType{Namespace: namespace.Val, Relation: relation.Val}
}

func (p *parser) parseType(endToken itemType) (types []ast.RelationType) {
	op := "union"

	for !p.fatal {
		var identifier item
		p.match(&identifier)
		var current ast.RelationType
		if op == "union" {
			if identifier.Val == "SubjectSet" {
				current = p.matchSubjectSet()
				types = append(types, current)
			} else {
				current = ast.RelationType{Namespace: identifier.Val}
				types = append(types, current)
				//@TODO: maybe ensureNamespaceExists to auto-create empty namespaces?
				p.addCheck(checkNamespaceExists(identifier))
			}
		} else {
			current = types[len(types)-1]
			if len(current.Types) == 0 {
				current.Types = append(current.Types, ast.RelationType{Namespace: current.Namespace, Relation: current.Relation})
				current.Namespace = ""
				current.Relation = ""
			}
			if identifier.Val == "SubjectSet" {
				current.Types = append(current.Types, p.matchSubjectSet())
			} else {
				current.Types = append(current.Types, ast.RelationType{Namespace: identifier.Val})
			}
			types[len(types)-1] = current
		}
		switch item := p.next(); item.Typ {
		case endToken:
			return
		case itemTypeUnion:
			op = "union"
		case itemTypeIntersection:
			op = "intersect"
		default:
			p.addFatal(item, "expected '|' or '&', got %q", item.Val)
		}
	}
	return
}

func (p *parser) parsePermits() {
	p.match("=", "{")
	for !p.fatal {
		switch itam := p.next(); itam.Typ {

		case itemBraceRight:
			return

		case itemIdentifier, itemStringLiteral:
			permission := itam.Val

			rewrite := simplifyExpression(p.parsePermissionExpressions(nil, itemOperatorComma, expressionNestingMaxDepth))
			if rewrite == nil {
				return
			}
			p.namespace.Relations = append(p.namespace.Relations,
				ast.Relation{
					Name:              permission,
					SubjectSetRewrite: rewrite,
				})

		default:
			p.addFatal(itam, "expected identifier or '}', got %s %q", itam.Typ.String(), itam.Val)
			return
		}
	}
}

func (p *parser) parsePermissionExpressions(root *ast.SubjectSetRewrite, finalToken itemType, depth int) *ast.SubjectSetRewrite {
	if depth <= 0 {
		p.addFatal(p.peek(),
			"expression nested too deeply; maximal nesting depth is %d",
			expressionNestingMaxDepth)
		return nil
	}

	// We only expect an expression in the beginning and after a binary
	// operator.
	expectExpression := true
	// the current context variable, i.e., this
	var ctx item

	// TODO(hperl): Split this into two state machines: One that parses an
	// expression or expression group; and one that parses a binary operator.
	for !p.fatal {
		switch itam := p.peek(); {
		case itam.Typ == itemOperatorColon:
			p.match(
				":", "(", "ctx", optional(":", "Context"), ")",
				optional(":", "boolean"),
			)
			// We just entered the permission definition, next should be itemOperatorArrow
		case itam.Typ == itemParenLeft:
			p.mark()
			switch {
			case p.matchIf(is(itemParenLeft), "(", &ctx):
				if ctx.Typ == itemParenLeft {
					p.restoreMark()
					itam = p.next()
					ctx.Reset()
					child := p.parsePermissionExpressions(nil, itemParenRight, depth-1)
					if child == nil {
						return nil
					}
					root = addChild(root, child)
					expectExpression = false
					break
				}
				switch {
				case p.matchIf(or(itemOperatorComma, itemParenRight), optional(","), ")", "=>"):
					// (x) => | (x,) =>
					// no push
				case p.matchIf(is(itemOperatorArrow), "=>"), p.matchIf(is(itemOperatorDot), "."):
					// (x. | (x =>
					// push it
					p.restoreMark()
					itam = p.next() // consume paren
					child := p.parsePermissionExpressions(nil, itemParenRight, depth-1)
					if child == nil {
						return nil
					}
					root = addChild(root, child)
					expectExpression = false
				}
			default:
				return nil
			}

		case itam.Typ == itemOperatorArrow:
			p.next() // consume operator

		case itam.Typ == finalToken:
			p.next() // consume final token
			return root

		case itam.Typ == itemOperatorComma:
			p.next() // consume comma that is not finalToken

		case itam.Typ == itemBraceRight:
			// We don't consume the '}' here, to allow `parsePermits` to consume
			// it.
			return root

		case itam.Typ == itemOperatorAnd, itam.Typ == itemOperatorOr:
			p.next() // consume operator

			// A nil root means that we saw a binary expression before the first
			// expression.
			if root == nil {
				return nil
			}
			newRoot := &ast.SubjectSetRewrite{
				Operation: setOperation(itam.Typ),
				Children:  []ast.Child{root},
			}
			root = newRoot
			expectExpression = true
			ctx.Reset()

		// A "not" creates an AST node where the children are either a
		// single expression, or a list of expressions grouped by "()".
		case itam.Typ == itemOperatorNot:
			p.next() // consume operator
			child := p.parseNotExpression(depth - 1)
			if child == nil {
				return nil
			}
			root = addChild(root, child)
			expectExpression = false

		case slices.Contains([]itemType{itemKeywordThis, itemIdentifier, itemStringLiteral}, itam.Typ), ctx.Typ == 0:
			p.matchIf(or(itemKeywordThis, itemIdentifier, itemStringLiteral), &ctx)

		default:
			// itam.Val here is usually (always?) '.'
			if !expectExpression {
				// Two expressions can't follow each other directly, they must
				// be separated by a binary operator.
				p.addFatal(itam, "did not expect another expression")
				return nil
			}
			child := p.parsePermissionExpression(depth - 1)
			if child == nil {
				return nil
			}
			root = addChild(root, child)
			expectExpression = true
		}
	}
	return nil
}

func (p *parser) parseNotExpression(depth int) ast.Child {
	if depth <= 0 {
		p.addFatal(p.peek(),
			"expression nested too deeply; maximal nesting depth is %d",
			expressionNestingMaxDepth)
		return nil
	}

	var (
		child ast.Child
		ctx   item
	)

	if itam := p.peek(); itam.Typ == itemParenLeft {
		p.next() // consume paren
		child = p.parsePermissionExpressions(nil, itemParenRight, depth-1)
	} else {
		p.match(&ctx)
		child = p.parsePermissionExpression(depth - 1)
	}
	if child == nil {
		return nil
	}
	return &ast.InvertResult{Child: child}
}

func addChild(root *ast.SubjectSetRewrite, child ast.Child) *ast.SubjectSetRewrite {
	if root == nil {
		return child.AsRewrite()
	} else {
		root.Children = append(root.Children, child)
		return root
	}
}

func setOperation(typ itemType) ast.Operator {
	switch typ {
	case itemOperatorAnd:
		return ast.OperatorAnd
	case itemOperatorOr:
		return ast.OperatorOr
	}
	panic("not reached")
}

func (p *parser) matchPropertyAccess(propertyName any) bool {
	return p.matchIf(is(itemBracketLeft), "[", propertyName, "]") || p.match(".", propertyName)
}

func (p *parser) parsePermissionExpression(depth int) (rewrite ast.Child) {
	if depth <= 0 {
		p.addFatal(p.peek(),
			"expression nested too deeply; maximal nesting depth is %d",
			expressionNestingMaxDepth)
		return nil
	}

	var relation, verb item

	switch {
	case p.matchIf(is(itemOperatorEquals), "=="):
		verb = p.peek()
		verb.Val = "equals"
		relation = item{Val: ""}
	case p.match(".", &verb):
		if verb.Val != "equals" && !p.matchPropertyAccess(&relation) {
			return
		}
	}

	switch verb.Val {
	case "equals":
		if !p.match(optional("("), "ctx", ".", "subject", optional(")")) {
			return
		}
		if frame, parentOk := p.peekFrame(); parentOk {
			rewrite = &ast.SubjectEqualsObject{
				TraversedTypes: frame.traversedTypes,
			}
		} else {
			// Otherwise create a subject set equals object
			rewrite = &ast.SubjectEqualsObject{}
		}
	case "related":
		if !p.match(".") {
			return
		}
		switch itam := p.next(); itam.Val {
		case "traverse":
			if !p.match("(") {
				return
			}
			// Push the current relation as a traversal frame
			p.pushFrame(relation)
			var children ast.Children
			// Parse the traversal expression(s)
			child := p.parsePermissionExpressions(nil, itemParenRight, depth-1)
			if child != nil {
				children = ast.Children{child}
			}
			if frame, ok := p.popFrame(); ok {
				if parent, pok := p.peekFrame(); pok {
					// if we're in a nested traversal, we need to check parent's traversalTypes for the relation in question
					//p.dump("nested traverse check: %s [%v] => %s", p.namespace.Name, frame.traversedTypes, relation.Val)
					p.addCheck(checkIdentifierTypesHaveRelation(&p.namespace, parent.traversedTypes, relation))
				} else {
					// otherwise, we're only interested in whether this namespace has the relation in question
					//p.dump("traverse check: %s => %s", p.namespace.Name, relation.Val)
					p.addCheck(checkCurrentNamespaceHasRelation(&p.namespace, relation))
				}

				rewrite = &ast.TupleToSubjectSet{
					TraversedTypes:             frame.traversedTypes,
					Relation:                   relation.Val,
					ComputedSubjectSetRelation: simplifyExpression(&ast.SubjectSetRewrite{Children: children}),
				}
			} else {
				p.addFatal(itam, "expected completion of traversal but frame context not found")
			}
		case "includes":
			if !p.match("(", "ctx", ".", "subject", optional(","), ")") {
				return nil
			}

			if parent, parentOk := p.peekFrame(); parentOk {
				// If we're in a traversal, just set the traversal's computed value so the result is a tuple to subject set
				//p.dump("nested includes check: %s %s => %s", p.namespace.Name, relationQuery(parent.traversedTypes), relation.Val)
				p.addCheck(checkIdentifierTypesHaveRelation(&p.namespace, parent.traversedTypes, relation))
			} else {
				// Otherwise create a computed subject set
				//p.dump("includes check: %s => %s", p.namespace.Name, relation.Val)
				p.addCheck(checkCurrentNamespaceHasRelation(&p.namespace, relation))
			}

			rewrite = &ast.ComputedSubjectSet{Relation: relation.Val}
		default:
			p.addFatal(itam, "expected 'traverse' or 'includes', got %q", itam.Val)
		}

	case "permits":
		if !p.match("(", "ctx", optional(","), ")") {
			return nil
		}
		if parent, parentOk := p.peekFrame(); parentOk {
			// If we're in a traversal, just set the traversal's computed value so the result is a tuple to subject set
			//p.dump("nested permits check: %s %s => %s", p.namespace.Name, relationQuery(parent.traversedTypes), relation.Val)
			p.addCheck(checkIdentifierTypesHaveRelation(&p.namespace, parent.traversedTypes, relation))
		} else {
			// Otherwise create a computed subject set
			//p.dump("permits check: %s => %s", p.namespace.Name, relation.Val)
			p.addCheck(checkCurrentNamespaceHasRelation(&p.namespace, relation))
		}

		rewrite = &ast.ComputedSubjectSet{Relation: relation.Val}
	default:
		p.addFatal(verb, "expected 'related' or 'permits', got %q", verb.Val)
	}

	return
}

// simplifyExpression rewrites the expression to use n-ary set operations
// instead of binary ones.
func simplifyExpression(root *ast.SubjectSetRewrite) *ast.SubjectSetRewrite {
	if root == nil {
		return nil
	}
	var newChildren []ast.Child
	for _, child := range root.Children {
		if ch, ok := child.(*ast.SubjectSetRewrite); ok && ch != nil && ch.Operation == root.Operation {
			// merge child and root
			simplifyExpression(ch)
			newChildren = append(newChildren, ch.Children...)
		} else {
			// can't merge, just copy
			newChildren = append(newChildren, child)
		}
	}
	root.Children = newChildren

	return root
}
