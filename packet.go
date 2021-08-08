package godns

import (
	"bytes"
	"encoding/binary"
	"fmt"

)

type Packet struct {
	Header
	Questions []Question
	Answers []Answer
	Authoritys []Authority
	Additionals []Additional
}

func NewPacket(data []byte) (*Packet, error) {
	packet := &Packet{}
	header, err := NewHeader(data[:12])
	if err != nil {
		return nil, err
	}
	packet.Header = *header
		offset := 12
	// question section
	questions := make([]Question, 0)
	for i := 0; i < int(header.Qdcount); i++ {
		d, err := DomainFromBytes(data[offset:])
		if err != nil {
			return nil, err
		}
		nameLen := 0
		for _, l := range d {
			nameLen += int(l.length) + 1
		}
		offset += nameLen
		typ := Type((uint16(data[offset]) << 8) + uint16(data[offset+1]))
		offset += 2
		class := Class((uint16(data[offset]) << 8) + uint16(data[offset+1]))
		offset += 2
		q := Question{
			Domain: d,
			Type: typ,
			Class: class,
		}
		questions = append(questions, q)
	}
	packet.Questions = questions
	// answer section
	answers := make([]Answer, 0)
	for i := 0; i < int(header.Ancount); i++ {
		d, err := DomainFromBytes(data[offset:])
		if err != nil {
			return nil, err
		}
		nameLen := 0
		for _, l := range d {
			nameLen += int(l.length) + 1
		}
		offset += nameLen
		typ := Type((uint16(data[offset]) << 8) + uint16(data[offset+1]))
		offset += 2
		class := Class((uint16(data[offset]) << 8) + uint16(data[offset+1]))
		offset += 2
		ttl := (uint32(data[offset]) << 24) + (uint32(data[offset+1]) << 16) + (uint32(data[offset+2]) << 8) + uint32(data[offset+3])
		offset += 4
		rdlength := (uint16(data[offset]) << 8) + uint16(data[offset+1])
		offset += 2
		ans := Answer{
			Domain: d,
			Type: typ,
			Class: class,
			Ttl: ttl,
			Rlength: rdlength,
			Rdata: data[offset: offset+int(rdlength)],
		}
		offset += int(rdlength)
		answers = append(answers, ans)
	}
	packet.Answers = answers
	// authority section
	authoritys := make([]Authority, 0)
	for i := 0; i < int(header.Nscount); i++ {
		d, err := DomainFromBytes(data[offset:])
		if err != nil {
			return nil, err
		}
		nameLen := 0
		for _, l := range d {
			nameLen += int(l.length) + 1
		}
		offset += nameLen
		typ := Type((uint16(data[offset]) << 8) + uint16(data[offset+1]))
		offset += 2
		class := Class((uint16(data[offset]) << 8) + uint16(data[offset+1]))
		offset += 2
		ttl := (uint32(data[offset]) << 24) + (uint32(data[offset+1]) << 16) + (uint32(data[offset+2]) << 8) + uint32(data[offset+3])
		offset += 4
		rdlength := (uint16(data[offset]) << 8) + uint16(data[offset+1])
		offset += 2
		auth := Authority{
			Domain: d,
			Type: typ,
			Class: class,
			Ttl: ttl,
			Rlength: rdlength,
			Rdata: data[offset: offset+int(rdlength)],
		}
		offset += int(rdlength)
		authoritys = append(authoritys, auth)
	}
	packet.Authoritys = authoritys
	// additional section
	additionals := make([]Additional, 0)
	for i := 0; i < int(header.Arcount); i++ {
		d, err := DomainFromBytes(data[offset:])
		if err != nil {
			return nil, err
		}
		nameLen := 0
		for _, l := range d {
			nameLen += int(l.length) + 1
		}
		offset += nameLen
		typ := Type((uint16(data[offset]) << 8) + uint16(data[offset+1]))
		offset += 2
		class := Class((uint16(data[offset]) << 8) + uint16(data[offset+1]))
		offset += 2
		ttl := (uint32(data[offset]) << 24) + (uint32(data[offset+1]) << 16) + (uint32(data[offset+2]) << 8) + uint32(data[offset+3])
		offset += 4
		rdlength := (uint16(data[offset]) << 8) + uint16(data[offset+1])
		offset += 2
		auth := Additional{
			Domain: d,
			Type: typ,
			Class: class,
			Ttl: ttl,
			Rlength: rdlength,
			Rdata: data[offset: offset+int(rdlength)],
		}
		offset += int(rdlength)
		additionals = append(additionals, auth)
	}
	packet.Additionals = additionals
	return packet, nil
}

func (p *Packet) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	hbuf, err := p.Header.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, hbuf...)
	for _, q := range p.Questions {
		buf = append(buf, q.Serialize()...)
	}
	for _, ans := range p.Answers {
		buf = append(buf, ans.Serialize()...)
	}
	for _, auth := range p.Authoritys {
		buf = append(buf, auth.Serialize()...)
	}
	for _, add := range p.Additionals {
		buf = append(buf, add.Serialize()...)
	}
	return buf, nil
}

type Header struct {
	Id uint16
	Qr bool
	Opcode Opcode
	AA bool
	TC bool
	RD bool
	RA bool
	AD bool
	CD bool
	RCode RCode
	Qdcount uint16
	Ancount uint16
	Nscount uint16
	Arcount uint16
}

type Opcode uint8

const (
	QUERY Opcode = 0
	IQUERY Opcode = 1
	STATUS Opcode = 2
	NOTIFY Opcode = 4
	UPDATE Opcode = 5
	DSO Opcode = 6 // DNS Statefull Operations
)

func (o Opcode) String() string {
	switch o {
	case QUERY:
		return "Query"
	case IQUERY:
		return "IQuery"
	case STATUS:
		return "Status"
	case NOTIFY:
		return "Notify"
	case UPDATE:
		return "Update"
	case DSO:
		return "DSO"
	default:
		return ""
	}
}

type Question struct {
	Domain Domain
	Type Type
	Class Class
}

func (q *Question) Serialize() []byte {
	buf := q.Domain.Bytes()
	tbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tbuf, uint16(q.Type))
	cbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(cbuf, uint16(q.Class))
	buf = append(buf, tbuf...)
	buf = append(buf, cbuf...)
	return buf
}

func NewQuestion(domain string, typ Type, class Class) (*Question, error) {
	d, err := NewDomain(domain)
	if err != nil {
		return nil, err
	}
	return &Question{
		Domain: d,
		Type: typ,
		Class: class,
	}, nil
}

type Answer struct {
	Domain Domain
	Type Type
	Class Class
	Ttl uint32
	Rlength uint16
	Rdata []byte
}

func NewAnswer(domain string, typ Type, class Class, ttl uint32, rdata []byte) (*Answer, error) {
	d, err := NewDomain(domain)
	if err != nil {
		return nil, err
	}
	return &Answer{
		Domain: d,
		Type: typ,
		Class: class,
		Ttl: ttl,
		Rlength: uint16(len(rdata)),
		Rdata: rdata,
	}, nil
}

func (a *Answer) Serialize() []byte {
	buf := a.Domain.Bytes()
	tbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tbuf, uint16(a.Type))
	cbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(cbuf, uint16(a.Class))
	buf = append(buf, tbuf...)
	buf = append(buf, cbuf...)
	ttbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(ttbuf, a.Ttl)
	rlbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(rlbuf, uint16(a.Rlength))
	buf = append(buf, ttbuf...)
	buf = append(buf, rlbuf...)
	buf = append(buf, a.Rdata...)
	return buf
}

type Authority struct {
	Domain Domain
	Type Type
	Class Class
	Ttl uint32
	Rlength uint16
	Rdata []byte
}

func NewAuthority(domain string, typ Type, class Class, ttl uint32, rdata []byte) (*Authority, error) {
	d, err := NewDomain(domain)
	if err != nil {
		return nil, err
	}
	return &Authority{
		Domain: d,
		Type: typ,
		Class: class,
		Ttl: ttl,
		Rlength: uint16(len(rdata)),
		Rdata: rdata,
	}, nil
}

func (auth *Authority) Serialize() []byte {
	buf := auth.Domain.Bytes()
	tbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tbuf, uint16(auth.Type))
	cbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(cbuf, uint16(auth.Class))
	buf = append(buf, tbuf...)
	buf = append(buf, cbuf...)
	ttbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(ttbuf, auth.Ttl)
	rlbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(rlbuf, uint16(auth.Rlength))
	buf = append(buf, ttbuf...)
	buf = append(buf, rlbuf...)
	buf = append(buf, auth.Rdata...)
	return buf
}

type Additional struct {
	Domain Domain
	Type Type
	Class Class
	Ttl uint32
	Rlength uint16
	Rdata []byte
}

func NewAdditional(domain string, typ Type, class Class, ttl uint32, rdata []byte) (*Additional, error) {
	d, err := NewDomain(domain)
	if err != nil {
		return nil, err
	}
	return &Additional{
		Domain: d,
		Type: typ,
		Class: class,
		Ttl: ttl,
		Rlength: uint16(len(rdata)),
		Rdata: rdata,
	}, nil
}

func (add *Additional) Serialize() []byte {
	buf := add.Domain.Bytes()
	tbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tbuf, uint16(add.Type))
	cbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(cbuf, uint16(add.Class))
	buf = append(buf, tbuf...)
	buf = append(buf, cbuf...)
	ttbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(ttbuf, add.Ttl)
	rlbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(rlbuf, uint16(add.Rlength))
	buf = append(buf, ttbuf...)
	buf = append(buf, rlbuf...)
	buf = append(buf, add.Rdata...)
	return buf
}

func NewHeader(data []byte) (*Header, error) {
	header := &Header{}
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.BigEndian, &header.Id); err != nil {
		return nil, err
	}
	var oct uint8
	if err := binary.Read(buf, binary.BigEndian, &oct); err != nil {
		return nil, err
	}
	qr := oct >> 7
	if qr == 1 {
		header.Qr = true
	} else {
		header.Qr = false
	}
	opcode := (0b01111000 & oct) >> 3
	header.Opcode = Opcode(opcode)
	if (0b00000100 & oct) != 0 {
		header.AA = true
	} else {
		header.AA = false
	}
	if (0b00000010 & oct) != 0 {
		header.TC = true
	} else {
		header.TC = false
	}
	if (0b00000001 & oct) != 0 {
		header.RD = true
	} else {
		header.RD = false
	}
	if err := binary.Read(buf, binary.BigEndian, &oct); err != nil {
		return nil, err
	}
	if (0b10000000 & oct) != 0 {
		header.RA = true
	} else {
		header.RA = false
	}
	if (0b00100000 & oct) != 0 {
		header.AD = true
	} else {
		header.AD = false
	}
	if (0b00010000 & oct) != 0 {
		header.CD = true
	} else {
		header.CD = false
	}
	rcode := 0b00001111 & oct
	header.RCode = RCode(rcode)
	if err := binary.Read(buf, binary.BigEndian, &header.Qdcount); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &header.Ancount); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &header.Nscount); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &header.Arcount); err != nil {
		return nil, err
	}
	return header, nil
}

func (h *Header) Serialize() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	if err := binary.Write(buf, binary.BigEndian, h.Id); err != nil {
		return nil, err
	}
	var oct uint8
	if h.Qr {
		oct += 0b10000000
	}
	oct = oct + (uint8(h.Opcode) << 3)
	if err := binary.Write(buf, binary.BigEndian, oct); err != nil {
		return nil, err
	}
	if h.AA {
		oct += 0b00000100
	}
	if h.TC {
		oct += 0b00000010
	}
	if h.RD {
		oct += 0b00000001
	}
	oct = uint8(0)
	if h.RA {
		oct += 0b10000000
	}
	if h.AD {
		oct += 0b00100000
	}
	if h.CD {
		oct += 0b00010000
	}
	oct = oct + uint8(h.RCode)
	if err := binary.Write(buf, binary.BigEndian, oct); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Qdcount); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Ancount); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Nscount); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, h.Arcount); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (h *Header) Show() {
	fmt.Println("DNS header")
	fmt.Printf("ID=%x\n", h.Id)
	fmt.Printf("Qr=%v\n", h.Qr)
	fmt.Printf("Opcode=%s\n", h.Opcode.String())
	fmt.Printf("AA=%v\n", h.AA)
	fmt.Printf("TC=%v\n", h.TC)
	fmt.Printf("RD=%v\n", h.RD)
	fmt.Printf("RA=%v\n", h.RA)
	fmt.Printf("AD=%v\n", h.AD)
	fmt.Printf("CD=%v\n", h.CD)
	fmt.Printf("Rcode=%v\n", h.RCode.Error())
	fmt.Printf("Qdcount=%d\n", h.Qdcount)
	fmt.Printf("Ancount=%d\n", h.Ancount)
	fmt.Printf("Nscount=%d\n", h.Nscount)
	fmt.Printf("Arcount=%d\n", h.Arcount)
}
