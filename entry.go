// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// File contains Entry structures and functions
package ldap

type Entry struct {
	DN         string
	Attributes map[string][]string
}

type EntryAttribute struct {
	Name   string
	Values []string
}

func (req *Entry) RecordType() uint8 {
	return EntryRecord
}

func NewEntry(dn string) *Entry {
	entry := &Entry{DN: dn}
	entry.Attributes = make(map[string][]string)
	return entry
}

// TODO: Proper LDIF writer, currently just for testing...
func (e *Entry) String() string {
	ldif := "dn: " + e.DN + "\n"
	for name, vals := range e.Attributes {
		for _, val := range vals {
			ldif += name + ": " + val + "\n"
		}
	}
	return ldif
}
