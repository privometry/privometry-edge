package cli

import "testing"

// scripted answers prompts in order and fails the test when it runs out.
type scripted struct {
	t       *testing.T
	lines   []string
	secrets []string
}

func (s *scripted) Line(prompt string) (string, error) {
	if len(s.lines) == 0 {
		s.t.Fatalf("unexpected prompt %q", prompt)
	}
	v := s.lines[0]
	s.lines = s.lines[1:]
	return v, nil
}

func (s *scripted) Secret(prompt string) (string, error) {
	if len(s.secrets) == 0 {
		s.t.Fatalf("unexpected secret prompt %q", prompt)
	}
	v := s.secrets[0]
	s.secrets = s.secrets[1:]
	return v, nil
}
