package alerts

import "strconv"

// OptimizeRow is one alert as a row of Upload: its card, the copies it
// notes or 1, its grade, and the price it waits for as the row's loaded
// price.
type OptimizeRow struct {
	CardID    string
	Quantity  int
	Condition string
	Price     string
}

// OptimizeRows are views as the Optimize button's rows, and whether Upload
// opens on buylist: the side of most of them, buylist on a tie. Upload
// merges rows of one card and grade, so each gets one row, from an alert on
// the opening side if any.
func OptimizeRows(views []View) ([]OptimizeRow, bool) {
	buylist := 0
	for _, view := range views {
		if view.Side == SideBuylist {
			buylist++
		}
	}
	side := SideRetail
	if buylist*2 >= len(views) {
		side = SideBuylist
	}

	var rows []OptimizeRow
	at := map[[2]string]int{}
	for _, view := range views {
		row := OptimizeRow{
			CardID:    view.CardID,
			Quantity:  max(view.Quantity, 1),
			Condition: view.Condition,
			Price:     strconv.FormatFloat(view.Target(), 'f', 2, 64),
		}
		key := [2]string{view.CardID, view.Condition}
		i, seen := at[key]
		if !seen {
			at[key] = len(rows)
			rows = append(rows, row)
		} else if view.Side == side {
			rows[i] = row
		}
	}
	return rows, side == SideBuylist
}

// DeepLink names what the alerts page was opened on, "" for the list.
func DeepLink(edit, card, remove string) string {
	switch {
	case edit != "":
		return "edit"
	case card != "":
		return "card"
	case remove != "":
		return "remove"
	}
	return ""
}

// Removing is the id of the listed alert remove names, 0 for none.
func Removing(views []View, remove string) int64 {
	id, err := strconv.ParseInt(remove, 10, 64)
	if err != nil {
		return 0
	}
	for _, view := range views {
		if view.ID == id {
			return id
		}
	}
	return 0
}
