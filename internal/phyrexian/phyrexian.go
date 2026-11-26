// Package phyrexian respells Phyrexian card names for the Phi normal font.
package phyrexian

import "strings"

// respeller maps the fan ELAJC ("Phi gibberish") encoding, which MTGJSON's
// Phyrexian flavorNames still use, letter by letter to Wizards' official
// orthography that Phi normal draws. A space in the old encoding is the
// blank sentence space, a comma the inked word divider.
var respeller = strings.NewReplacer(
	" ", "\u2002",
	"$", "n",
	"%", "ķ",
	"&", "z",
	",", " ",
	".", ".",
	"A", "č",
	"B", "ǩ",
	"C", "q",
	"D", "'",
	"E", "i",
	"F", "ə",
	"G", "ɢ",
	"J", "ž",
	"K", "ð",
	"L", "s",
	"M", "ʁ",
	"N", "ŋ",
	"O", "ø",
	"P", "π",
	"Q", "h",
	"R", "ɮ",
	"S", "χ",
	"T", "ť",
	"U", "ɒ",
	"V", "ɬ",
	"W", "ẅ",
	"Y", "u",
	"Z", "θ",
	"_", "ǥ",
	"a", "ǆ",
	"b", "b",
	"c", "l",
	"d", "d",
	"e", "a",
	"f", "φ",
	"g", "š",
	"h", "k",
	"i", "f",
	"k", "g",
	"l", "v",
	"m", "m",
	"n", "ɴ",
	"o", "o",
	"p", "p",
	"r", "r",
	"s", "x",
	"t", "t",
	"u", "e",
	"v", "w",
	"w", "j",
	"y", "y",
	"z", "ɣ",
	"|", "^",
)

// Respell returns a Phyrexian name in the official orthography. Every name
// in the old encoding opens with "|", and one in the new spelling opens
// with "^", so a name without the "|" is returned as it is.
func Respell(name string) string {
	if !strings.HasPrefix(name, "|") {
		return name
	}
	return respeller.Replace(name)
}
