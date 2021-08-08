package godns

import (
	"testing"
)

var EXAMPLE_COM_BYTES = []byte{0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00}
var VENERA_ISI_EDU_AND_TYPE_BYTES = []byte{0x06, 0x76, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x03, 0x69, 0x73, 0x69, 0x03, 0x65, 0x64, 0x75, 0x00, 0x20, 0x20, 0x21, 0x21}

var VENERA_ISI_EDU_BYTES = []byte{0x06, 0x76, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x03, 0x69, 0x73, 0x69, 0x03, 0x65, 0x64, 0x75, 0x00}

func TestType(t *testing.T) {
	if int(A) != 1 {
		t.Fatalf("expected A(1) type. actual : %d", A)
	}
	if int(NS) != 2 {
		t.Fatalf("expected NS(2) type. actual : %d", NS)
	}
	if int(TXT) != 16 {
		t.Fatalf("expected TXT(16) type. actual : %d", TXT)
	}
}

func TestDomain_NewDomain(t *testing.T) {
	name1 := "XX.LCS.MIT.EDU"
	domain1, err := NewDomain(name1)
	if err != nil {
		t.Fatal(err)
	}
	if len(domain1) != 5 {
		t.Fatalf("wanted of label length is 4, actual %d", len(domain1))
	}
	name2 := "VENERA.ISI.EDU."
	domain2, err := NewDomain(name2)
	if err != nil {
		t.Fatal(err)
	}
	if len(domain2) != 5 {
		t.Fatalf("wanted of label length is 4, actual %d", len(domain1))
	}
	if string(domain2[0].data) != "venera" {
		t.Fatalf("wanted venera, actual %s", string(domain2[0].data))
	}
	if domain2[3].length != 0 {
		t.Fatalf("wanted 0, actual %d", domain2[0].length)
	}
	name3 := "4.3.2.1.in-addr.arpa"
	domain3, err := NewDomain(name3)
	if err != nil {
		t.Fatal(err)
	}
	if string(domain3[0].data) != "4" {
		t.Fatalf("wanted 4, actual %s", string(domain3[0].data))
	}
}

func TestDomain_DomainFromBytes(t *testing.T) {
	domain1, err := DomainFromBytes(EXAMPLE_COM_BYTES)
	if err != nil {
		t.Fatal(err)
	}
	if string(domain1[0].data) != "example" {
		t.Fatalf("wanted example, actual %s", string(domain1[0].data))
	}
	domain2, err := DomainFromBytes(VENERA_ISI_EDU_AND_TYPE_BYTES)
	if err != nil {
		t.Fatal(err)
	}
	if string(domain2[2].data) != "edu" {
		t.Fatalf("wanted edu, actual %s", string(domain2[2].data))
	}
}

func TestDomain_Bytes(t *testing.T) {
	d, err := NewDomain("venera.isi.edu")
	if err != nil {
		t.Fatal(err)
	}
	data := d.Bytes()
	if len(data) != len(VENERA_ISI_EDU_BYTES) {
		t.Fatalf("invalid data length: wanted %d, actual %d", len(VENERA_ISI_EDU_BYTES), len(data))
	}
}

func TestDomain_String(t *testing.T) {
	domain, err := NewDomain("VENERA.ISI.EDU.")
	if err != nil {
		t.Fatal(err)
	}
	if domain.String() != "venera.isi.edu." {
		t.Fatalf("wanted venera.isi.edu., actual %s", domain.String())
	}
}
