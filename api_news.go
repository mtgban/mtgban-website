package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// newsNow is the clock the API reads, a variable for tests.
var newsNow = time.Now

// newsColumn is a report column past the card fields, as the API lists it.
type newsColumn struct {
	Field    string `json:"field"`
	Title    string `json:"title"`
	Kind     string `json:"kind"`
	Sortable bool   `json:"sortable"`
}

// newsCardFields are the Head fields a row carries as its card fields instead.
var newsCardFields = []string{"product_name", "set_name", "product_number", "variant"}

// newsColumns lists a report's visible columns past the card fields, ranking first.
func newsColumns(page NewspaperPage) []newsColumn {
	var out []newsColumn
	for _, h := range page.Head {
		if h.IsHidden || h.Field == "" || slices.Contains(newsCardFields, h.Field) {
			continue
		}
		kind := "text"
		switch {
		case h.IsDollar:
			kind = "dollar"
		case h.IsPerc:
			kind = "percent"
		case h.IsNum:
			kind = "number"
		}
		out = append(out, newsColumn{Field: h.Field, Title: h.Title, Kind: kind, Sortable: h.CanSort})
	}
	return out
}

// newsFilters names the filter options a report takes.
func newsFilters(page NewspaperPage) []string {
	filters := []string{"set", "rarity", "finish"}
	if page.HasBucket {
		filters = append(filters, "bucket")
	}
	if page.Priced != "" {
		filters = append(filters, "min_price", "max_price")
	}
	if page.PercChanged != "" {
		filters = append(filters, "min_change", "max_change")
	}
	return filters
}

// newsOptions are every option a report can take; other query keys are ignored.
var newsOptions = []string{"sort", "dir", "set", "rarity", "finish", "bucket", "min_price", "max_price", "min_change", "max_change"}

// newsSortAliases maps the API's names for the card fields to their Head fields.
var newsSortAliases = map[string]string{"name": "product_name", "set": "set_name", "number": "product_number", "finish": "variant"}

// newsValues drops the blank entry the page's dropdowns lead with.
func newsValues(values []string) []string {
	out := []string{}
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// newsReports are the reports this deployment serves: declared, shown, and with a live edition.
func newsReports() []NewspaperPage {
	var out []NewspaperPage
	for _, page := range GetNewspaperPages() {
		if page.Query == "" || !page.shown() || len(page.Results) == 0 {
			continue
		}
		out = append(out, page)
	}
	return out
}

// newsDate is a report's calc_date, the day of its live edition.
func newsDate(page NewspaperPage) string {
	if len(page.Results) == 0 {
		return ""
	}
	d := page.Results[0].Date
	if len(d) > 10 {
		d = d[:10]
	}
	return d
}

// newsRefreshed formats the cache's update time for meta and headers.
func newsRefreshed(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// newsReport describes one report in reports.json.
type newsReport struct {
	Key         string       `json:"key"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Columns     []newsColumn `json:"columns"`
	Filters     []string     `json:"filters"`
	Sets        []string     `json:"sets"`
	Finishes    []string     `json:"finishes"`
	Buckets     []string     `json:"buckets,omitempty"`
	Rows        int          `json:"rows"`
}

// newsListMeta is reports.json's meta.
type newsListMeta struct {
	Latest    string `json:"latest"`
	Refreshed string `json:"refreshed"`
	Stale     bool   `json:"stale"`
}

// newsReportMeta is a report response's meta.
type newsReportMeta struct {
	Report    string       `json:"report"`
	Title     string       `json:"title"`
	Date      string       `json:"date"`
	Refreshed string       `json:"refreshed"`
	Stale     bool         `json:"stale"`
	Rows      int          `json:"rows"`
	Columns   []newsColumn `json:"columns"`
}

// newsError answers an error with its status and no caching.
func newsError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Cache-Control", "no-store")
	errorResponse(w, status, msg)
}

// newsParseQuery validates a report request's options into a query, or says what is wrong.
func newsParseQuery(page NewspaperPage, values url.Values) (newsQuery, error) {
	accepted := append([]string{"sort", "dir"}, newsFilters(page)...)
	for _, opt := range newsOptions {
		if values.Has(opt) && !slices.Contains(accepted, opt) {
			return newsQuery{}, fmt.Errorf("%s does not take %s", page.Option, opt)
		}
	}

	q := newsQuery{Sort: cmp.Or(values.Get("sort"), "ranking")}
	if field, ok := newsSortAliases[q.Sort]; ok {
		q.Sort = field
	} else if !slices.ContainsFunc(newsColumns(page), func(c newsColumn) bool { return c.Field == q.Sort && c.Sortable }) {
		return newsQuery{}, fmt.Errorf("cannot sort %s by %q", page.Option, q.Sort)
	}
	q.Dir = values.Get("dir")
	switch q.Dir {
	case "":
		q.Dir = "desc"
		if q.Sort == "ranking" {
			q.Dir = "asc"
		}
	case "asc", "desc":
	default:
		return newsQuery{}, fmt.Errorf("dir must be asc or desc, not %q", q.Dir)
	}

	q.Set, q.Finish, q.Rarity, q.Bucket = values.Get("set"), values.Get("finish"), values.Get("rarity"), values.Get("bucket")
	if q.Set != "" && !slices.Contains(page.AvailableEditions, q.Set) {
		return newsQuery{}, fmt.Errorf("set %q is not in %s, reports.json lists its sets", q.Set, page.Option)
	}
	if q.Finish != "" && !slices.Contains(page.PossibleFinish, q.Finish) {
		return newsQuery{}, fmt.Errorf("finish %q is not in %s, reports.json lists its finishes", q.Finish, page.Option)
	}
	if rarities := newsValues(NewspaperAllRarities); q.Rarity != "" && !slices.Contains(rarities, q.Rarity) {
		return newsQuery{}, fmt.Errorf("rarity must be one of %s", strings.Join(rarities, ", "))
	}
	if buckets := newsValues(BucketNames); q.Bucket != "" && !slices.Contains(buckets, q.Bucket) {
		return newsQuery{}, fmt.Errorf("bucket must be one of %s", strings.Join(buckets, ", "))
	}

	for _, bound := range []struct {
		name string
		dst  **float64
	}{{"min_price", &q.MinPrice}, {"max_price", &q.MaxPrice}, {"min_change", &q.MinChange}, {"max_change", &q.MaxChange}} {
		v, err := newsParseBound(values.Get(bound.name))
		if err != nil {
			return newsQuery{}, fmt.Errorf("%s must be a number", bound.name)
		}
		*bound.dst = v
	}
	return q, nil
}

// newsReportsJSON is reports.json's body.
func newsReportsJSON(reports []NewspaperPage, refreshed time.Time, stale bool) ([]byte, error) {
	out := struct {
		Meta    newsListMeta `json:"meta"`
		Reports []newsReport `json:"reports"`
	}{Meta: newsListMeta{Refreshed: newsRefreshed(refreshed), Stale: stale}}
	for _, page := range reports {
		if d := newsDate(page); d > out.Meta.Latest {
			out.Meta.Latest = d
		}
		report := newsReport{
			Key: page.Option, Title: page.Title, Description: page.Desc,
			Columns: newsColumns(page), Filters: newsFilters(page),
			Sets: newsValues(page.AvailableEditions), Finishes: newsValues(page.PossibleFinish),
			Rows: len(page.Results),
		}
		if page.HasBucket {
			report.Buckets = newsValues(BucketNames)
		}
		out.Reports = append(out.Reports, report)
	}
	body, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// newsCardKeys are the card fields every row carries after ranking.
var newsCardKeys = []string{"id", "name", "set", "number", "finish", "rarity"}

// newsCardValues are a row's card fields, in newsCardKeys order.
func newsCardValues(r NewspaperResult) []string {
	return []string{r.UUID, r.CardName, r.Edition, r.Number, r.Variant, r.Rarity}
}

// newsNumber is a numeric column's value as JSON: 0 when absent, null when not finite.
func newsNumber(r NewspaperResult, field string) string {
	v, err := strconv.ParseFloat(r.FieldValue(field), 64)
	if err != nil {
		return "0"
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "null"
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// newsRowJSON writes one row as an object: ranking, the card fields, then the report's columns.
func newsRowJSON(buf *bytes.Buffer, r NewspaperResult, cols []newsColumn) error {
	buf.WriteString(`{"ranking":` + strconv.Itoa(r.Ranking))
	values := newsCardValues(r)
	for i, key := range newsCardKeys {
		v, err := json.Marshal(values[i])
		if err != nil {
			return err
		}
		buf.WriteString(`,"` + key + `":`)
		buf.Write(v)
	}
	for _, c := range cols {
		if c.Field == "ranking" {
			continue
		}
		k, err := json.Marshal(c.Field)
		if err != nil {
			return err
		}
		buf.WriteByte(',')
		buf.Write(k)
		buf.WriteByte(':')
		if c.Kind != "text" {
			buf.WriteString(newsNumber(r, c.Field))
			continue
		}
		v, err := json.Marshal(r.FieldValue(c.Field))
		if err != nil {
			return err
		}
		buf.Write(v)
	}
	buf.WriteByte('}')
	return nil
}

// newsReportJSON is a report's body: meta, then the rows with their keys in column order.
func newsReportJSON(meta newsReportMeta, rows []NewspaperResult) ([]byte, error) {
	head, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(`{"meta":`)
	buf.Write(head)
	buf.WriteString(`,"rows":[`)
	for i, row := range rows {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := newsRowJSON(&buf, row, meta.Columns); err != nil {
			return nil, err
		}
	}
	buf.WriteString("]}\n")
	return buf.Bytes(), nil
}

// newsWrite sends a successful body.
func newsWrite(w http.ResponseWriter, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Write(body)
}

// NewspaperAPI serves /api/v2/newspaper/: reports.json, the reports this game
// carries, and {report}.json, one report's live edition filtered and sorted.
// docs/api-v2-newspaper.md has the shape.
func (s *site) NewspaperAPI(w http.ResponseWriter, r *http.Request) {
	b := s.backend()
	sig := r.FormValue("sig")
	if !canAccessMode(strings.Split(GetParamFromSig(sig, "APImode"), ","), "newspaper") {
		newsError(w, http.StatusForbidden, "plan does not include newspaper")
		return
	}
	key, isJSON := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/api/v2/newspaper/"), ".json")
	if !isJSON || key == "" || strings.Contains(key, "/") {
		newsError(w, http.StatusNotFound, "Not found")
		return
	}
	reports := newsReports()
	if len(reports) == 0 {
		w.Header().Set("Retry-After", "300")
		newsError(w, http.StatusServiceUnavailable, "the newspaper is not loaded yet")
		return
	}
	refreshed := GetLastNewspaperUpdate()
	stale := newsStale(refreshed, newsNow())

	if key == "reports" {
		body, err := newsReportsJSON(reports, refreshed, stale)
		if err != nil {
			newsError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		newsWrite(w, "application/json", body)
		return
	}

	i := slices.IndexFunc(reports, func(p NewspaperPage) bool { return p.Option == key })
	if i < 0 {
		newsError(w, http.StatusBadRequest, fmt.Sprintf("unknown report %q, reports.json lists them", key))
		return
	}
	page := reports[i]
	q, err := newsParseQuery(page, r.URL.Query())
	if err != nil {
		newsError(w, http.StatusBadRequest, err.Error())
		return
	}
	rows := newsFilter(b, page, page.Results, q)
	cols := newsColumns(page)
	meta := newsReportMeta{
		Report: page.Option, Title: page.Title, Date: newsDate(page),
		Refreshed: newsRefreshed(refreshed), Stale: stale, Rows: len(rows), Columns: cols,
	}
	body, err := newsReportJSON(meta, rows)
	if err != nil {
		newsError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	newsWrite(w, "application/json", body)
}
