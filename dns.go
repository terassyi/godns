package godns

import (
	"strings"
	"fmt"
)

type Class uint16

const (
	IN Class = 1
	CS Class = 2
	CH Class = 3
	HS Class = 4
)

func (c Class) String() string {
	switch c {
	case IN :
		return "IN"
	case CS:
		return "CS"
	case CH:
		return "CH"
	case HS:
		return "HS"
	default:
		return fmt.Sprintf("%d", int(c))
	}
}

type Type uint16

const (
	A Type = 1
	NS Type = 2
	MD Type = 3
	MF Type = 4
	CNAME Type = 5
	SOA Type = 6
	MB Type = 7
	MG Type = 8
	MR Type = 9
	NULL Type = 10
	WKS Type = 11
	PTR Type = 12
	HINFO Type = 13
	MINFO Type = 14
	MX Type = 15
	TXT Type = 16
)

func (t Type) String() string {
	switch t {
	case A:
		return "A"
	case NS:
		return "NS"
	case MD:
		return "MD"
	case MF:
		return "MF"
	case CNAME:
		return "CNAME"
	case SOA:
		return "SOA"
	case MB:
		return "MB"
	case MG:
		return "MG"
	case MR:
		return "MR"
	case NULL:
		return "NULL"
	case WKS:
		return "WKS"
	case PTR:
		return "PTR"
	case HINFO:
		return "HINFO"
	case MINFO:
		return "MINFO"
	case MX:
		return "MX"
	case TXT:
		return "TXT"
	default:
		return ""
	}
}

type RCode uint8

const (
	NoError RCode = 0
	FormErr RCode = 1
	ServFail RCode = 2
	NXDomain RCode = 3
	NotImp RCode   = 4
	Refused RCode  = 5
	YXDomain RCode = 6
	YXRRSet RCode  = 7
	NXRRSet RCode  = 8
	NotAuth RCode  = 9
	NotZone RCode  = 10
	DSOTYPENI RCode= 11
	BADVERS RCode  = 16
	BADSIG RCode   = 16
	BADKEY RCode   = 17
	BADTIME RCode  = 18
	BADMODE RCode  = 19
	BADNAME RCode  = 20
	BADALG RCode   = 21
	BADTRUNC RCode = 22
	BADCOOKIE RCode= 23
)

func (e RCode) Error() error {
	switch e {
	case FormErr:
		return fmt.Errorf("Format Error")
	case ServFail:
		return fmt.Errorf("Server Failure")
	case NXDomain:
		return fmt.Errorf("Non-Existent Domain")
	case NotImp:
		return fmt.Errorf("Not Implemented")
	case Refused:
		return fmt.Errorf("Query Refused")
	case YXDomain:
		return fmt.Errorf("Name Exists when it should not")
	case YXRRSet:
		return fmt.Errorf("RR Set Exists when it should not")
	case NXRRSet:
		return fmt.Errorf("RR Set that should not exist does not")
	case NotAuth:
		return fmt.Errorf("Not Authorized")
	case NotZone:
		return fmt.Errorf("Name not contained in zone")
	case DSOTYPENI:
		return fmt.Errorf("DSO-TYPE Not Implemented")
	case BADVERS:
		return fmt.Errorf("Bad OPT Version or TSIG Signature Failure")
	case BADKEY:
		return fmt.Errorf("Key not recognized")
	case BADTIME:
		return fmt.Errorf("Signature out of time window")
	case BADMODE:
		return fmt.Errorf("Bad TKEY Mode")
	case BADNAME:
		return fmt.Errorf("Duplicate key name")
	case BADALG:
		return fmt.Errorf("Algorithm not supported")
	case BADTRUNC:
		return fmt.Errorf("Bad Truncation")
	case BADCOOKIE:
		return fmt.Errorf("Bad/missing Server Cookie")
	default:
		return nil
	}
}

type label struct {
	length uint8
	data []byte
}

type Domain []label

func NewDomain(domain string) (Domain, error){
	elms := strings.Split(domain, ".")
	if len(elms) == 0 {
		return nil, fmt.Errorf("invalid domain name")
	}
	labels := make([]label, 0)
	for _, e := range elms {
		label := label{
			length: uint8(len(e)),
			data: []byte(strings.ToLower(e)),
		}
		labels = append(labels ,label)
	}
	labels = append(labels, label{length: 0, data: nil})
	return labels, nil
}

func DomainFromBytes(data []byte) (Domain, error) {
	labels := make([]label, 0)
	for i := 0; i < len(data); i++ {
		if data[i] == 0 {
			l := label{
				length: uint8(0),
				data: nil,
			}
			labels = append(labels, l)
			break
		}
		if data[i] < 64 {
			l := label{
				length: uint8(data[i]),
				data: data[i+1:i+int(data[i])+1],
			}
			labels = append(labels, l)
			i += int(l.length)
		} else {
			// compress
		}
	}
	return labels, nil
}

func (d Domain) String() string {
	name := ""
	for _, l := range d {
		if l.length == 0 {
			name += "."
			break
		}
		name += string(l.data)
		name += "."
	}
	return name[:len(name)-1]
}

func (d Domain) Bytes() []byte {
	data := make([]byte, 0)
	for _, l := range d {
		if l.length == 0 {
			data = append(data, byte(0))
			break
		}
		data = append(data, byte(l.length))
		data = append(data, l.data...)
	}
	return data
}
