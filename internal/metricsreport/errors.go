package metricsreport

import (
	"fmt"
	"strconv"

	"github.com/mtgban/mtgban-website/observability"
)

// errorName is the registry name behind every script error row.
const errorName = "ui.js.error"

// errorRowHelp says what an error row counts; a row merges errors and rejections.
const errorRowHelp = "A script error or an unhandled promise rejection, by script, line and type."

// ErrorLabel names one error row: "navbar.js:42 TypeError", or "other ScriptError" at line 0.
func ErrorLabel(script string, line int, class string) string {
	if line == 0 {
		return script + " " + class
	}
	return script + ":" + strconv.Itoa(line) + " " + class
}

// ErrorSignals turns one build's top error rows into Invest's Failures rows: counts, with no rate or trend.
func ErrorSignals(rows []observability.ErrorTop, build string) []Signal {
	if len(rows) == 0 {
		return nil
	}
	short := build[:min(7, len(build))]
	out := make([]Signal, 0, len(rows))
	for _, r := range rows {
		out = append(out, Signal{
			Section:  SectionFailures,
			Label:    ErrorLabel(r.Script, r.Line, r.Class),
			Name:     errorName,
			Scope:    r.Script,
			Value:    r.Class,
			Evidence: fmt.Sprintf("build %s, desktop %d, mobile %d, since %s", short, r.Desktop, r.Mobile, r.FirstDay.Format("2006-01-02")),
			Count:    r.N,
			Help:     errorRowHelp,
		})
	}
	return out
}
