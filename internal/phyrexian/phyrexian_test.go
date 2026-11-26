package phyrexian

import "testing"

func TestRespell(t *testing.T) {
	tests := []struct {
		card, name, want string
	}{
		{"Ajani, Sleeper Agent (DMU 370)", "|DFaUnEED lugtkenvr.", "^'əǆɒɴii' veštgaɴwr."},
		{"Elesh Norn, Mother of Machines (ONE 414)", "|Ducg,norn wUDkJUKM.", "^'elš ɴorɴ jɒ'gžɒðʁ."},
		{"Jace, the Perfected Mind (ONE 325)", "|auL wne%m,DtFRErt.", "^ǆes jɴaķm 'təɮirt."},
		{"Inkmoth Nexus (SLD 1207)", "|dceb&aiyccDFCd.", "^dlabzǆfyll'əqd."},
		{"Psychosis Crawler (PW22 6)", "|wE_kzvEDl,bvudn.", "^jiǥgɣwi'v bwedɴ."},
		{"Lukka, Bound to Ruin (ONE 328)", "|cyhYD hu$t,QivuJp.", "^lyku' kent hfwežp."},
		{"already respelled", "^'elš ɴorɴ jɒ'gžɒðʁ.", "^'elš ɴorɴ jɒ'gžɒðʁ."},
	}
	for _, tt := range tests {
		got := Respell(tt.name)
		if got != tt.want {
			t.Errorf("%s: Respell(%q) = %q, want %q", tt.card, tt.name, got, tt.want)
		}
	}
}
