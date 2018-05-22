package main

import (
	"strings"
	"fmt"
)

func (p *OAuthProxy) incrementBasicSuccess(entryAlias string, method string) {
	prefix := "basicAuth.authenticated"
	entryAlias = strings.Replace(entryAlias, ".", "-", -1)
	entryMetricName := fmt.Sprintf("%s.%s.%s", prefix, entryAlias, method)
	totalMetricName := fmt.Sprintf("%s.total", prefix)
	p.StatsD.Increment(entryMetricName)
	p.StatsD.Increment(totalMetricName)
}

func (p *OAuthProxy) incrementBasicFailed(method string) {
	prefix := "basicAuth.unauthenticated"
	entryMetricName := fmt.Sprintf("%s.attemptedWith.%s", prefix, method)
	totalMetricName := fmt.Sprintf("%s.total", prefix)
	p.StatsD.Increment(entryMetricName)
	p.StatsD.Increment(totalMetricName)
}