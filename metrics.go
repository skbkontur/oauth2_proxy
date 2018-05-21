package main

import (
	"strings"
	"fmt"


	"github.com/rainycape/unidecode"
	"github.com/skbkontur/oauth2_proxy/providers"
)

func (p *OAuthProxy) incrementAuthenticated(session *providers.SessionState, method string) {
	if len(session.Groups) > 0 {
		for _, group := range session.Groups {
			groupAlias := unidecode.Unidecode(group)
			groupAlias = strings.Replace(groupAlias, ".", "-", -1)
			metricName := fmt.Sprintf("authenticated.Oauth2.%s.%s", groupAlias, method)
			p.StatsD.Increment(metricName)
		}
	} else {
		if p.PassBasicAuth && len(session.User) > 0 {
			userAlias := unidecode.Unidecode(session.User)
			userAlias = strings.Replace(userAlias, ".", "-", -1)
			metricName := fmt.Sprintf("authenticated.BasicAuth.%s.%s", userAlias, method)
			p.StatsD.Increment(metricName)
		}
	}
}

func (p *OAuthProxy) incrementUnauthenticated(method string, returnedStatus string) {
	metricName := fmt.Sprintf("unauthenticated.%s.resultedWith.%s", method, returnedStatus)
	p.StatsD.Increment(metricName)
}
