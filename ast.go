package gnata

import (
	"strconv"

	"github.com/recolabs/gnata/internal/parser"
)

// ASTNode is a public, read-only snapshot of a parsed JSONata AST node.
//
// It intentionally copies the internal parser tree instead of exposing
// internal/parser.Node directly, keeping the public API stable while allowing
// callers to build tooling such as linters, dependency scanners, and policy
// validators.
type ASTNode struct {
	Type   string
	Value  string
	Pos    int
	NumVal float64
	Quoted bool

	Steps       []*ASTNode
	Expressions []*ASTNode
	LHS         []*ASTNode
	Arguments   []*ASTNode

	Body      *ASTNode
	Procedure *ASTNode

	Left  *ASTNode
	Right *ASTNode

	Expression *ASTNode

	Condition *ASTNode
	Then      *ASTNode
	Else      *ASTNode

	Terms []ASTSortTerm

	Pattern *ASTNode
	Update  *ASTNode
	Delete  *ASTNode

	Stages []ASTStage
	Group  *ASTGroupExpr

	KeepArray          bool
	KeepSingletonArray bool
	ConsArray          bool
	Thunk              bool
	Tuple              bool

	Focus string
	Index string
}

// ASTSortTerm is one term in a sort expression.
type ASTSortTerm struct {
	Descending bool
	Expression *ASTNode
}

// ASTStage is a predicate or index binding attached to a path step.
type ASTStage struct {
	Type       string
	Expression *ASTNode
	VarName    string
	Pos        int
}

// ASTGroupExpr holds key-value pairs of a group expression.
type ASTGroupExpr struct {
	Pairs [][2]*ASTNode
	Pos   int
}

// Analysis contains structural facts collected from a JSONata expression.
type Analysis struct {
	AST           *ASTNode
	References    []Reference
	FunctionCalls []FunctionCall
}

// Reference is a static path-like reference found in an expression.
//
// Root is "$" for the context value, "$name" for variables, and "name" for
// bare field roots. Segments contains the simple path segments following Root.
// Dynamic is true when the reference continues through a non-static path step.
type Reference struct {
	Root     string
	Segments []PathSegment
	Pos      int
	Dynamic  bool
}

// PathSegment is one static member/index segment of a Reference.
type PathSegment struct {
	Text   string
	Pos    int
	Quoted bool
	Index  bool
}

// FunctionCall is a JSONata function call found in an expression.
type FunctionCall struct {
	Name string
	Pos  int
}

// Parse parses a JSONata expression and returns a processed public AST.
func Parse(expr string) (*ASTNode, error) {
	ast, err := parseInternalAST(expr)
	if err != nil {
		return nil, err
	}
	return cloneASTNode(expr, ast), nil
}

// Analyze parses a JSONata expression and returns a processed AST plus
// structural facts collected from it.
func Analyze(expr string) (*Analysis, error) {
	ast, err := parseInternalAST(expr)
	if err != nil {
		return nil, err
	}
	return analyzeInternalAST(expr, ast), nil
}

// AST returns a public, read-only snapshot of the compiled expression AST.
func (e *Expression) AST() *ASTNode {
	if e == nil {
		return nil
	}
	return cloneASTNode(e.src, e.ast)
}

// Analysis returns structural facts collected from the compiled expression.
func (e *Expression) Analysis() *Analysis {
	if e == nil {
		return nil
	}
	return analyzeInternalAST(e.src, e.ast)
}

func parseInternalAST(expr string) (*parser.Node, error) {
	p := parser.NewParser(expr)
	ast, err := p.Parse()
	if err != nil {
		return nil, err
	}
	return parser.ProcessAST(ast)
}

func analyzeInternalAST(src string, ast *parser.Node) *Analysis {
	state := analysisState{src: src}
	state.walk(ast, map[string]int{}, false)
	return &Analysis{
		AST:           cloneASTNode(src, ast),
		References:    state.references,
		FunctionCalls: state.functions,
	}
}

type analysisState struct {
	src        string
	references []Reference
	functions  []FunctionCall
}

func (s *analysisState) walk(node *parser.Node, bound map[string]int, functionProcedure bool) {
	if node == nil {
		return
	}

	switch node.Type {
	case parser.NodeBlock:
		childBound := cloneBound(bound)
		for _, expr := range node.Expressions {
			if expr != nil && expr.Type == parser.NodeBind && expr.Left != nil {
				s.walk(expr.Right, childBound, false)
				childBound[expr.Left.Value]++
				continue
			}
			s.walk(expr, childBound, false)
		}
		return

	case parser.NodeBind:
		s.walk(node.Right, bound, false)
		return

	case parser.NodeLambda:
		childBound := cloneBound(bound)
		for _, arg := range node.Arguments {
			if arg != nil && arg.Type == parser.NodeVariable {
				childBound[arg.Value]++
			}
		}
		s.walk(node.Body, childBound, false)
		return

	case parser.NodeFunction, parser.NodePartial:
		if name, ok := functionCallName(node.Procedure); ok {
			s.functions = append(s.functions, FunctionCall{Name: name, Pos: node.Pos})
		} else {
			s.walk(node.Procedure, bound, true)
		}
		for _, arg := range node.Arguments {
			s.walk(arg, bound, false)
		}
		return

	case parser.NodePath:
		s.collectPathReference(node, bound)
		s.walkPathDynamicParts(node, bound)
		return

	case parser.NodeVariable:
		if !functionProcedure && !isBoundVariable(node.Value, bound) {
			s.references = append(s.references, Reference{
				Root: variableRoot(node.Value),
				Pos:  node.Pos,
			})
		}
		return

	case parser.NodeName:
		s.references = append(s.references, Reference{
			Root: node.Value,
			Pos:  node.Pos,
		})
		return
	}

	s.walkChildren(node, bound)
}

func (s *analysisState) collectPathReference(node *parser.Node, bound map[string]int) {
	if node == nil || len(node.Steps) == 0 {
		return
	}
	first := node.Steps[0]
	if first == nil {
		return
	}

	ref := Reference{Pos: first.Pos}
	switch first.Type {
	case parser.NodeVariable:
		if isBoundVariable(first.Value, bound) {
			return
		}
		ref.Root = variableRoot(first.Value)
	case parser.NodeName:
		ref.Root = first.Value
	default:
		return
	}

	for _, step := range node.Steps[1:] {
		segments, ok := s.pathSegmentsFromNode(step)
		if !ok {
			ref.Dynamic = true
			break
		}
		ref.Segments = append(ref.Segments, segments...)
	}
	s.references = append(s.references, ref)
}

func (s *analysisState) walkPathDynamicParts(node *parser.Node, bound map[string]int) {
	for _, step := range node.Steps {
		if step == nil {
			continue
		}
		for _, stage := range step.Stages {
			s.walk(stage.Expression, bound, false)
		}
		if step.Group != nil {
			s.walkGroup(step.Group, bound)
		}
		if isSimplePathStep(step) {
			continue
		}
		if step.Type == parser.NodeBinary && step.Value == "[" {
			s.walk(step.Right, bound, false)
			continue
		}
		s.walk(step, bound, false)
	}
	if node.Group != nil {
		s.walkGroup(node.Group, bound)
	}
}

func (s *analysisState) walkChildren(node *parser.Node, bound map[string]int) {
	for _, child := range node.Expressions {
		s.walk(child, bound, false)
	}
	for _, child := range node.LHS {
		s.walk(child, bound, false)
	}
	for _, child := range node.Arguments {
		s.walk(child, bound, false)
	}
	s.walk(node.Body, bound, false)
	s.walk(node.Procedure, bound, false)
	s.walk(node.Left, bound, false)
	s.walk(node.Right, bound, false)
	s.walk(node.Expression, bound, false)
	s.walk(node.Condition, bound, false)
	s.walk(node.Then, bound, false)
	s.walk(node.Else, bound, false)
	for _, term := range node.Terms {
		s.walk(term.Expression, bound, false)
	}
	s.walk(node.Pattern, bound, false)
	s.walk(node.Update, bound, false)
	s.walk(node.Delete, bound, false)
	for _, stage := range node.Stages {
		s.walk(stage.Expression, bound, false)
	}
	if node.Group != nil {
		s.walkGroup(node.Group, bound)
	}
}

func (s *analysisState) walkGroup(group *parser.GroupExpr, bound map[string]int) {
	if group == nil {
		return
	}
	for _, pair := range group.Pairs {
		s.walk(pair[0], bound, false)
		s.walk(pair[1], bound, false)
	}
}

func functionCallName(node *parser.Node) (string, bool) {
	if node == nil {
		return "", false
	}
	switch node.Type {
	case parser.NodeVariable, parser.NodeName:
		return node.Value, true
	default:
		return "", false
	}
}

func (s *analysisState) pathSegmentsFromNode(node *parser.Node) ([]PathSegment, bool) {
	if node == nil {
		return nil, false
	}
	switch node.Type {
	case parser.NodeName, parser.NodeString:
		return []PathSegment{{Text: node.Value, Pos: node.Pos, Quoted: astNodeQuoted(s.src, node)}}, true
	case parser.NodeNumber:
		text := node.Value
		if text == "" {
			text = strconv.FormatFloat(node.NumVal, 'f', -1, 64)
		}
		return []PathSegment{{Text: text, Pos: node.Pos}}, true
	case parser.NodeBinary:
		if node.Value != "[" {
			return nil, false
		}
		left, ok := s.pathSegmentsFromNode(node.Left)
		if !ok {
			return nil, false
		}
		index, ok := s.staticArrayIndexSegment(node.Right)
		if !ok {
			return nil, false
		}
		return append(left, index), true
	default:
		return nil, false
	}
}

func (s *analysisState) staticArrayIndexSegment(node *parser.Node) (PathSegment, bool) {
	if node == nil || node.Type != parser.NodeNumber {
		return PathSegment{}, false
	}
	text := node.Value
	if text == "" {
		text = strconv.FormatFloat(node.NumVal, 'f', -1, 64)
	}
	return PathSegment{Text: text, Pos: node.Pos, Index: true}, true
}

func isSimplePathStep(node *parser.Node) bool {
	if node == nil {
		return false
	}
	switch node.Type {
	case parser.NodeVariable, parser.NodeName, parser.NodeString, parser.NodeNumber:
		return true
	case parser.NodeBinary:
		if node.Value != "[" || node.Right == nil || node.Right.Type != parser.NodeNumber {
			return false
		}
		return isSimplePathStep(node.Left)
	default:
		return false
	}
}

func variableRoot(name string) string {
	if name == "" {
		return "$"
	}
	return "$" + name
}

func isBoundVariable(name string, bound map[string]int) bool {
	return bound[name] > 0
}

func cloneBound(bound map[string]int) map[string]int {
	ret := make(map[string]int, len(bound))
	for key, value := range bound {
		ret[key] = value
	}
	return ret
}

func cloneASTNode(src string, node *parser.Node) *ASTNode {
	if node == nil {
		return nil
	}
	ret := &ASTNode{
		Type:               node.Type,
		Value:              node.Value,
		Pos:                node.Pos,
		NumVal:             node.NumVal,
		Quoted:             astNodeQuoted(src, node),
		KeepArray:          node.KeepArray,
		KeepSingletonArray: node.KeepSingletonArray,
		ConsArray:          node.ConsArray,
		Thunk:              node.Thunk,
		Tuple:              node.Tuple,
		Focus:              node.Focus,
		Index:              node.Index,
	}
	ret.Steps = cloneASTNodes(src, node.Steps)
	ret.Expressions = cloneASTNodes(src, node.Expressions)
	ret.LHS = cloneASTNodes(src, node.LHS)
	ret.Arguments = cloneASTNodes(src, node.Arguments)
	ret.Body = cloneASTNode(src, node.Body)
	ret.Procedure = cloneASTNode(src, node.Procedure)
	ret.Left = cloneASTNode(src, node.Left)
	ret.Right = cloneASTNode(src, node.Right)
	ret.Expression = cloneASTNode(src, node.Expression)
	ret.Condition = cloneASTNode(src, node.Condition)
	ret.Then = cloneASTNode(src, node.Then)
	ret.Else = cloneASTNode(src, node.Else)
	ret.Pattern = cloneASTNode(src, node.Pattern)
	ret.Update = cloneASTNode(src, node.Update)
	ret.Delete = cloneASTNode(src, node.Delete)
	if len(node.Terms) > 0 {
		ret.Terms = make([]ASTSortTerm, 0, len(node.Terms))
		for _, term := range node.Terms {
			ret.Terms = append(ret.Terms, ASTSortTerm{
				Descending: term.Descending,
				Expression: cloneASTNode(src, term.Expression),
			})
		}
	}
	if len(node.Stages) > 0 {
		ret.Stages = make([]ASTStage, 0, len(node.Stages))
		for _, stage := range node.Stages {
			ret.Stages = append(ret.Stages, ASTStage{
				Type:       stage.Type,
				Expression: cloneASTNode(src, stage.Expression),
				VarName:    stage.VarName,
				Pos:        stage.Pos,
			})
		}
	}
	ret.Group = cloneASTGroup(src, node.Group)
	return ret
}

func cloneASTNodes(src string, nodes []*parser.Node) []*ASTNode {
	if len(nodes) == 0 {
		return nil
	}
	ret := make([]*ASTNode, 0, len(nodes))
	for _, node := range nodes {
		ret = append(ret, cloneASTNode(src, node))
	}
	return ret
}

func cloneASTGroup(src string, group *parser.GroupExpr) *ASTGroupExpr {
	if group == nil {
		return nil
	}
	ret := &ASTGroupExpr{Pos: group.Pos}
	if len(group.Pairs) > 0 {
		ret.Pairs = make([][2]*ASTNode, 0, len(group.Pairs))
		for _, pair := range group.Pairs {
			ret.Pairs = append(ret.Pairs, [2]*ASTNode{
				cloneASTNode(src, pair[0]),
				cloneASTNode(src, pair[1]),
			})
		}
	}
	return ret
}

func astNodeQuoted(src string, node *parser.Node) bool {
	if node == nil {
		return false
	}
	if node.Type == parser.NodeString {
		return true
	}
	return node.Pos >= 0 && node.Pos < len(src) && src[node.Pos] == '"'
}
