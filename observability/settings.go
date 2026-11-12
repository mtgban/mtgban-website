package observability

// Setting is one stored reader setting the reports read.
type Setting struct {
	Name      string   // cookie or localStorage key; "Cookie.flag" for a packed flag
	Storage   string   // cookie, local, both
	Mirror    string   // for "both": the other copy's key, so a pair is one entry
	Path      string   // root, upload, arbit, reverse, global, sleepers, newspaper
	Kind      string   // flag, enum, number, list, blob, query
	Enum      []string // the values an enum setting takes
	Default   string   // the value a reader has before changing it
	Class     string   // preference, transient, admin
	Area      string   // the registry area it belongs to
	Fact      string   // the server name behind "requests that ran with it"
	FactScope string   // that name's scope, when it has one
	FactValue string   // that name's value, when it has one
}

// Settings returns every registered setting; empty until phase 2e fills it.
func Settings() []Setting {
	return nil
}
