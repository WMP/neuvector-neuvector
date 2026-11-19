package rest

import (
	"testing"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
)

func TestValidateAdmCtrlCriteriaModules(t *testing.T) {
	options := map[string]*api.RESTAdmissionRuleOption{share.CriteriaKeyModules: {}}
	for value, wantErr := range map[string]bool{
		"vim, vim=1.*, log4j-core>=2.0.0<2.17.1": false,
		"vim, log4j<1.0 x":                       true,
		"<1.0":                                   true,
	} {
		crt := &share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyModules, Op: share.CriteriaOpContainsAny, Value: value}
		err := validateAdmCtrlCriteria([]*share.CLUSAdmRuleCriterion{crt}, options, api.ValidatingDenyRuleType)
		if (err != nil) != wantErr {
			t.Errorf("value %q: err=%v wantErr=%v", value, err, wantErr)
		}
	}
}
