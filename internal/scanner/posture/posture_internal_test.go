package posture

import "testing"

func TestSensitiveKey(t *testing.T) {
	for key, want := range map[string]bool{
		"GITHUB_PERSONAL_ACCESS_TOKEN": true, "AWS_SECRET_ACCESS_KEY": true, "apiKey": true, "api_key": true,
		"password": true, "DB_PASSWORD": true, "clientSecret": true, "x-api-key": true, "privateKey": true,
		"claudeCodeFirstTokenDate": false, "tokenizer": false, "maxTokens": false, "keyboard": false,
		"primaryKey": false, "AWS_REGION": false, "secretName": false,
	} {
		if got := sensitiveKey(key); got != want {
			t.Errorf("sensitiveKey(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestIsLiteralSecret(t *testing.T) {
	for v, want := range map[string]bool{
		"fake-literal-token-value-1234": true, "${GITHUB_TOKEN}": false, "$TOKEN": false, "op://vault/item/field": false,
		"2026-01-02T10:00:00.000Z": false, "1234567890": false, "short": false, "two words here": false,
	} {
		if got := isLiteralSecret(v); got != want {
			t.Errorf("isLiteralSecret(%q) = %v, want %v", v, got, want)
		}
	}
}
