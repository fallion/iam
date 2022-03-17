package okta

import (
	"testing"
	//"fmt"

	cfg "github.com/kiwicom/iam/configs"
	"github.com/stretchr/testify/assert"
)

func TestJoinOktaURL(t *testing.T) {
	tests := map[string]struct {
		baseURL string
		UserID  string
		filters []string
		wantURL string
		wantErr bool
	}{
		"simple URL": {
			baseURL: "http://okta.com/",
			UserID:  "",
			filters: []string{},
			wantURL: "http://okta.com/groups",
			wantErr: false,
		},
		"URL + UserID": {
			baseURL: "http://okta.com/",
			UserID:  "42",
			filters: []string{},
			wantURL: "http://okta.com/users/42/groups",
			wantErr: false,
		},
		"URL + UserID + Filter": {
			baseURL: "http://okta.com/",
			UserID:  "42",
			filters: []string{"lastMembershipUpdated gt time"},
			wantURL: "http://okta.com/users/42/groups?filter=lastMembershipUpdated+gt+time",
			wantErr: false,
		},
		"URL + UserID + 2 Filters": {
			baseURL: "http://okta.com/",
			UserID:  "42",
			filters: []string{"lastMembershipUpdated gt time", "type eq \"OKTA_GROUP\""},
			wantURL: "http://okta.com/users/42/groups?filter=lastMembershipUpdated+gt+time+and+type+eq+%22OKTA_GROUP%22",
			wantErr: false,
		},
		"URL + Filter": {
			baseURL: "http://okta.com/",
			UserID:  "",
			filters: []string{"lastMembershipUpdated gt time"},
			wantURL: "http://okta.com/groups?filter=lastMembershipUpdated+gt+time",
			wantErr: false,
		},
	}

	for name, test := range tests {
		test := test

		t.Run(name, func(t *testing.T) {
			var oktaCfg cfg.OktaConfig
			oktaCfg.URL = test.baseURL
			oktaCfg.Filter = ""
			c := NewClient(&ClientOpts{
				OktaConfig: &oktaCfg,
			})
			gotURL, gotErr := c.joinOktaURLGroups(test.UserID, test.filters)

			if test.wantErr {
				assert.Error(t, gotErr)
			} else {
				assert.NoError(t, gotErr)
				assert.Equal(t, test.wantURL, gotURL)
			}
		})
	}
}
