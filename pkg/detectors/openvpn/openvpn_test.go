package openvpn

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validClientID       = "H-IyMCPZj4DJhmri60908NY.TqE0u"
	invalidClientID     = "H-IyMCPZj4DJhm?i60908NY.TqE0u"
	validClientSecret   = "KoBB7qmuBIvgqr_uC8OR-lNIm_8SPKRqqUvk-4bAFNNgivl8RFEO9pSbKXxHAmq753QFimSaC-V91h8tlipArc_"
	invalidClientSecret = "KoBB7qmuBIv?qr_uC8OR-lNIm_8SPKRqqUvk-4bAFNNgivl8RFEO9pSbKXxHAmq753QFimSaC-V91h8tlipArc_"
	inputDomain         = "pzUwgmXv5iKlMz9voI8gVVmWrtBzi.api"
	validDomain         = "https://pzUwgmXv5iKlMz9voI8gVVmWrtBzi.api.openvpn.com"
	invalidDomain       = "https://pzUwgmXv5iKlMz9voI?gVVmWrtBzi.api.openvpn.com"
	keyword             = "openvpn"
)

func TestOpenvpn_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword openvpn",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, validClientID, keyword, validClientSecret, keyword, validDomain),
			want:  []string{validClientID + validClientSecret, inputDomain + validClientSecret},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, invalidClientID, keyword, invalidClientSecret, keyword, invalidDomain),
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
