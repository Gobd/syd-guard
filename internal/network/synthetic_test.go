package network

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestSyntheticDNSSeparatesHostnamesAndNeverReassigns(t *testing.T) {
	mapping := NewSynthetic()
	first, err := mapping.Address("google.com")
	if err != nil {
		t.Fatal(err)
	}
	again, err := mapping.Address("GOOGLE.COM.")
	if err != nil || first != again {
		t.Fatal("canonical hostname address changed")
	}
	other, err := mapping.Address("other.example.com")
	if err != nil || first == other {
		t.Fatal("different hosts share synthetic identity")
	}
	if host, ok := mapping.Host(first); !ok || host != "google.com" {
		t.Fatal("lost mapping")
	}
}

func TestDNSAnswerDoesNotApproveOrGuessPort(t *testing.T) {
	mapping := NewSynthetic()
	dns := &DNS{synthetic: mapping}
	question := dnsmessage.Question{Name: dnsmessage.MustNewName("google.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{question}}
	packet, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	answer, err := dns.answer(packet)
	if err != nil {
		t.Fatal(err)
	}
	var result dnsmessage.Message
	if err := result.Unpack(answer); err != nil {
		t.Fatal(err)
	}
	if result.ID != 42 || len(result.Answers) != 1 || result.Answers[0].Header.TTL != 60 {
		t.Fatalf("invalid answer: %+v", result)
	}
	policy, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Pending()) != 0 || len(policy.Rules()) != 0 {
		t.Fatal("DNS alone created port/transport policy")
	}
	question.Type = dnsmessage.TypeAAAA
	message.Questions = []dnsmessage.Question{question}
	packet, err = message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	answer, err = dns.answer(packet)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Unpack(answer); err != nil {
		t.Fatal(err)
	}
	if len(result.Answers) != 0 {
		t.Fatal("unsupported IPv6 was silently granted")
	}
}
