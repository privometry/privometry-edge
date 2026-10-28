package content

import "sort"

// keywordIndex finds every detector keyword in one pass over the text, with
// an Aho-Corasick automaton. Matching folds ASCII letters to lower case,
// which is all keywords need: they are cheap prefilters, not patterns.
type keywordIndex struct {
	next [][256]int32  // goto function, completed with failure links
	out  [][]keywordAt // keywords ending at each node
}

type keywordAt struct {
	detector int // index into Engine.detectors
	length   int
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 'a' - 'A'
	}
	return b
}

func newKeywordIndex(ds []*Compiled) *keywordIndex {
	k := &keywordIndex{next: make([][256]int32, 1), out: make([][]keywordAt, 1)}
	for di, d := range ds {
		for _, w := range d.keywords {
			node := int32(0)
			for i := 0; i < len(w); i++ {
				c := lowerASCII(w[i])
				if k.next[node][c] == 0 {
					k.next = append(k.next, [256]int32{})
					k.out = append(k.out, nil)
					k.next[node][c] = int32(len(k.next) - 1)
				}
				node = k.next[node][c]
			}
			k.out[node] = append(k.out[node], keywordAt{detector: di, length: len(w)})
		}
	}
	// Breadth-first: complete the goto function with failure transitions and
	// inherit the outputs of each node's failure node.
	fail := make([]int32, len(k.next))
	var queue []int32
	for c := range 256 {
		if n := k.next[0][c]; n != 0 {
			queue = append(queue, n)
		}
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		k.out[node] = append(k.out[node], k.out[fail[node]]...)
		for c := range 256 {
			child := k.next[node][c]
			if child == 0 {
				k.next[node][c] = k.next[fail[node]][c]
				continue
			}
			fail[child] = k.next[fail[node]][c]
			queue = append(queue, child)
		}
	}
	return k
}

// find returns, per detector, the start offsets of its keyword hits.
func (k *keywordIndex) find(text string, n int) [][]int {
	hits := make([][]int, n)
	node := int32(0)
	for i := 0; i < len(text); i++ {
		node = k.next[node][lowerASCII(text[i])]
		for _, o := range k.out[node] {
			hits[o.detector] = append(hits[o.detector], i+1-o.length)
		}
	}
	return hits
}

// lines indexes line starts so each keyword hit finds its line in O(log n).
type lines []int

func newLines(text string) lines {
	ls := lines{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			ls = append(ls, i+1)
		}
	}
	return ls
}

// bounds returns the start and end (exclusive, before the newline) of the
// line holding offset i in a text of length n.
func (ls lines) bounds(i, n int) (int, int) {
	j := sort.SearchInts(ls, i+1) - 1
	end := n
	if j+1 < len(ls) {
		end = ls[j+1] - 1
	}
	return ls[j], end
}
