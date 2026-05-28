package gnata_test

import (
	"slices"
	"testing"

	"github.com/recolabs/gnata"
)

func TestAnalyzeCollectsVariablePathReferences(t *testing.T) {
	analysis, err := gnata.Analyze(`{"id": $nodes."scan-task".output.id, "flow": $playbook.inputs."flow-id"}`)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	got := referenceStrings(analysis.References)
	want := []string{"$nodes.scan-task.output.id", "$playbook.inputs.flow-id"}
	for _, ref := range want {
		if !slices.Contains(got, ref) {
			t.Fatalf("references = %#v, want %s", got, ref)
		}
	}

	var quotedNode, quotedInput bool
	for _, ref := range analysis.References {
		if ref.Root == "$nodes" && len(ref.Segments) > 0 && ref.Segments[0].Text == "scan-task" {
			quotedNode = ref.Segments[0].Quoted
		}
		if ref.Root == "$playbook" && len(ref.Segments) > 1 && ref.Segments[1].Text == "flow-id" {
			quotedInput = ref.Segments[1].Quoted
		}
	}
	if !quotedNode || !quotedInput {
		t.Fatalf("quoted segments not preserved: %#v", analysis.References)
	}
}

func TestAnalyzeCollectsFunctionCalls(t *testing.T) {
	analysis, err := gnata.Analyze(`($x := "$nodes.scan.output.id"; $eval($x) & $string($nodes.scan.output.id))`)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	got := functionNames(analysis.FunctionCalls)
	for _, name := range []string{"eval", "string"} {
		if !slices.Contains(got, name) {
			t.Fatalf("function calls = %#v, want %s", got, name)
		}
	}
	if slices.Contains(referenceStrings(analysis.References), "$nodes.scan.output.id") {
		return
	}
	t.Fatalf("references = %#v, want $nodes.scan.output.id", analysis.References)
}

func TestAnalyzeHonorsLocalVariableBindings(t *testing.T) {
	analysis, err := gnata.Analyze(`($nodes := {"scan": {"output": {"id": "local"}}}; $nodes.scan.output.id)`)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	for _, ref := range analysis.References {
		if ref.Root == "$nodes" {
			t.Fatalf("references = %#v, did not expect locally bound $nodes", analysis.References)
		}
	}
}

func TestAnalyzeCollectsStaticArrayIndexPathReferences(t *testing.T) {
	analysis, err := gnata.Analyze(`$poll.items[0][1].status`)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	got := referenceStrings(analysis.References)
	if slices.Contains(got, "items") {
		t.Fatalf("references = %#v, did not expect subscript path step internals", got)
	}
	if !slices.Contains(got, "$poll.items.0.1.status") {
		t.Fatalf("references = %#v, want $poll.items.0.1.status", got)
	}
	for _, ref := range analysis.References {
		if ref.Root == "$poll" && ref.Dynamic {
			t.Fatalf("reference = %#v, did not expect static array index to be dynamic", ref)
		}
		if ref.Root == "$poll" {
			for _, segment := range ref.Segments {
				if (segment.Text == "0" || segment.Text == "1") && !segment.Index {
					t.Fatalf("segment = %#v, want static array index marker", segment)
				}
			}
		}
	}
}

func TestAnalyzeDistinguishesDotNumberPathSegments(t *testing.T) {
	analysis, err := gnata.Analyze(`$poll.items.0.status`)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	for _, ref := range analysis.References {
		if ref.Root != "$poll" {
			continue
		}
		for _, segment := range ref.Segments {
			if segment.Text == "0" && segment.Index {
				t.Fatalf("segment = %#v, did not expect dot-number member to be marked as array index", segment)
			}
		}
	}
}

func TestAnalyzeKeepsDynamicArrayIndexPathReferencesDynamic(t *testing.T) {
	analysis, err := gnata.Analyze(`$poll.items[$i].status`)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	got := referenceStrings(analysis.References)
	if slices.Contains(got, "items") {
		t.Fatalf("references = %#v, did not expect subscript path step internals", got)
	}
	var foundPoll bool
	for _, ref := range analysis.References {
		if ref.Root == "$poll" {
			foundPoll = true
			if !ref.Dynamic {
				t.Fatalf("reference = %#v, want dynamic", ref)
			}
			if len(ref.Segments) != 0 {
				t.Fatalf("reference = %#v, want dynamic root prefix $poll", ref)
			}
		}
	}
	if !foundPoll {
		t.Fatalf("references = %#v, want $poll dynamic reference", got)
	}
	if !slices.Contains(got, "$i") {
		t.Fatalf("references = %#v, want dynamic index variable $i", got)
	}
}

func referenceStrings(refs []gnata.Reference) []string {
	ret := make([]string, 0, len(refs))
	for _, ref := range refs {
		text := ref.Root
		for _, segment := range ref.Segments {
			text += "." + segment.Text
		}
		ret = append(ret, text)
	}
	return ret
}

func functionNames(calls []gnata.FunctionCall) []string {
	ret := make([]string, 0, len(calls))
	for _, call := range calls {
		ret = append(ret, call.Name)
	}
	return ret
}
