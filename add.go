// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"fmt"
	"github.com/mavricknz/asn1-ber"
)

type AddRequest struct {
	Entry    *Entry
	Controls []Control
}

func (req *AddRequest) RecordType() uint8 {
	return AddRecord
}

func (l *LDAPConnection) Add(req *AddRequest) error {
	messageID, ok := l.nextMessageID()
	if !ok {
		return NewLDAPError(ErrorClosing, "messageID channel is closed.")
	}

	encodedAdd, err := encodeAddRequest(req)
	if err != nil {
		return err
	}

	packet, err := requestBuildPacket(messageID, encodedAdd, req.Controls)
	if err != nil {
		return err
	}

	return l.sendReqRespPacket(messageID, packet)
}

/*
   AddRequest ::= [APPLICATION 8] SEQUENCE {
        entry           LDAPDN,
        attributes      AttributeList }

   AttributeList ::= SEQUENCE OF attribute Attribute

   Attribute ::= SEQUENCE {
        type       AttributeDescription,
        vals       SET OF value AttributeValue } // vals is not empty
*/
func encodeAddRequest(addReq *AddRequest) (*ber.Packet, error) {
	addPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationAddRequest, nil, ApplicationMap[ApplicationAddRequest])
	addPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, addReq.Entry.DN, "LDAP DN"))

	attributeList := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "AttributeList")

	for name,values := range addReq.Entry.Attributes {
		attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
		attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, name, "Attribute Desc"))
		if len(values) == 0 {
			return nil, NewLDAPError(ErrorEncoding, "attribute "+name+" had no values.")
		}
		valuesSet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Attribute Value Set")
		for _, val := range values {
			valuesSet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, val, "AttributeValue"))
		}
		attribute.AppendChild(valuesSet)
		attributeList.AppendChild(attribute)
	}
	addPacket.AppendChild(attributeList)
	return addPacket, nil
}

func (req *AddRequest) Bytes() []byte {
	encoded, _ := encodeAddRequest(req)
	return encoded.Bytes()
}

func NewAddRequest(dn string) (req *AddRequest) {
	req = &AddRequest{Entry: NewEntry(dn), Controls: make([]Control, 0)}
	return
}

func (req *AddRequest) AddAttribute(attr *EntryAttribute) {
	req.Entry.Attributes[attr.Name] = attr.Values
}

func (req *AddRequest) AddAttributes(attrs []EntryAttribute) {
	for _, attr := range attrs {
		req.Entry.Attributes[attr.Name] = attr.Values
	}
}

// DumpAddRequest - Basic LDIF "like" dump for testing, no formating, etc
func (addReq *AddRequest) String() (dump string) {
	dump = fmt.Sprintf("dn: %s\n", addReq.Entry.DN)
	for name,values := range addReq.Entry.Attributes {
		for _, val := range values {
			dump += fmt.Sprintf("%s: %s\n", name, val)
		}
	}
	dump += fmt.Sprintf("\n")
	return
}

func (req *AddRequest) AddControl(control Control) {
	if req.Controls == nil {
		req.Controls = make([]Control, 0)
	}
	req.Controls = append(req.Controls, control)
}
