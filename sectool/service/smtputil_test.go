package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractEmailTo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers string
		want    []string
	}{
		{name: "single_address", headers: "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: test", want: []string{"recipient@example.com"}},
		{name: "angle_bracket_address", headers: "From: sender@example.com\r\nTo: \"Recipient Name\" <recipient@example.com>\r\nSubject: test", want: []string{"recipient@example.com"}},
		{name: "multiple_addresses", headers: "To: alice@example.com, Bob <bob@example.com>\r\nSubject: test", want: []string{"alice@example.com", "bob@example.com"}},
		{name: "folded_header", headers: "To: \"Recipient\" <recipient@example.com>,\r\n second@example.com\r\nSubject: test", want: []string{"recipient@example.com", "second@example.com"}},
		{name: "bare_lf", headers: "From: sender@example.com\nTo: recipient@example.com\nSubject: test", want: []string{"recipient@example.com"}},
		{name: "no_to_header", headers: "From: sender@example.com\r\nSubject: test", want: nil},
		{name: "case_insensitive", headers: "TO: recipient@example.com\r\nSubject: test", want: []string{"recipient@example.com"}},
		{name: "quoted_display_name_with_comma", headers: "To: \"Doe, Jane\" <jane@example.com>, bob@example.com\r\nSubject: test", want: []string{"jane@example.com", "bob@example.com"}},
		{name: "empty_headers", headers: "", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractEmailTo(tt.headers))
		})
	}
}
