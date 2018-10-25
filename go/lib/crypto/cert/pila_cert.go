package cert

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/util"
)

// type PilaCertificateEntity interface {
// 	MarshalText() ([]byte, error)
// 	UnmarshalText(text []byte) error
// 	Eq(o PilaCertificateEntity) bool
// }

// todo(cyrill): add type byte to allow different implementation of subject
type PilaCertificateEntity struct {
	Ipv4 net.IP
}

func (e PilaCertificateEntity) MarshalText() ([]byte, error) {
	return e.Ipv4.MarshalText()
}

func (e *PilaCertificateEntity) UnmarshalText(text []byte) error {
	return (&e.Ipv4).UnmarshalText(text)
}

func (e PilaCertificateEntity) Eq(o PilaCertificateEntity) bool {
	if reflect.TypeOf(e).Kind() != reflect.TypeOf(o).Kind() {
		return false
	}
	eip := e.Ipv4
	oip := o.Ipv4
	return eip.Equal(oip)
}

// Chain contains three certificates, one for the endpoint, one for the leaf,
// and one for the issuer. The endpoint certificate is a PilaCertificate signing
// the EndpointIdentifier of an endpoint (e.g. IPv4) and is signed by the leaf
// certificate. The leaf certificate is signed by the issuer certificate, which
// is signed by the TRC of the corresponding ISD.
type PilaChain struct {
	Endpoint *PilaCertificate `json:"0"`
	// Leaf is the leaf certificate of the chain. It is signed by the Issuer certificate.
	Leaf *Certificate `json:"1"`
	// Issuer is the issuer AS certificate of the chain. It is signed by the TRC of the ISD.
	Issuer *Certificate `json:"2"`
}

func (c *PilaChain) JSON(indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(c, "", strings.Repeat(" ", 4))
	}
	return json.Marshal(c)
}

func PilaChainFromRaw(raw common.RawBytes) (*PilaChain, error) {
	c := &PilaChain{}
	// maybe set empty struct instantiations in pilachain?
	// c := &PilaChain{Issuer: PilaCertificateIpv4Entity{}, Subject: PilaCertificateIpv4Entity{}}
	//todo(cyrill): How to make Unmarshal work with interfaces?
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *PilaChain) Verify(subject PilaCertificateEntity, t *trc.TRC) error {
	// Verify trc -> issuer -> leaf
	var certSlice []*Certificate
	certSlice = append(certSlice, c.Leaf)
	certSlice = append(certSlice, c.Issuer)
	chain, err := ChainFromSlice(certSlice)
	if err != nil {
		return err
	}
	if err := chain.Verify(c.Leaf.Subject, t); err != nil {
		return err
	}

	// Verify leaf -> endpoint
	// check signalgo
	if c.Leaf.SignAlgorithm != crypto.Ed25519 {
		return errors.New("Only signature algorithm: " + crypto.Ed25519 + " is currently allowed")
	}
	// verify signature
	if err := c.Endpoint.Verify(subject, c.Leaf.SubjectSignKey, c.Leaf.SignAlgorithm); err != nil {
		return err
	}
	return nil
}

func (c *PilaChain) String() string {
	return fmt.Sprintf("CertificateChain %sv%d", c.Endpoint.Subject, c.Endpoint.Version)

}

type PilaCertificate struct {
	// CanIssue describes whether the subject is able to issue certificates.
	CanIssue bool
	// Comment is an arbitrary and optional string used by the subject to describe the certificate.
	Comment string
	// EncAlgorithm is the algorithm associated with SubjectEncKey.
	EncAlgorithm string
	// ExpirationTime is the unix timestamp in seconds at which the certificate expires.
	ExpirationTime uint64
	// Issuer is the certificate issuer. It can only be a issuing AS.
	Issuer addr.IA
	// IssuingTime is the unix timestamp in seconds at which the certificate was created.
	IssuingTime uint64
	// SignAlgorithm is the algorithm associated with SubjectSigKey.
	SignAlgorithm string
	// Signature is the certificate signature. It is computed over the rest of the certificate.
	Signature common.RawBytes `json:",omitempty"`
	// Subject is the certificate subject.
	Subject PilaCertificateEntity
	// SubjectEncKey is the public key used for encryption.
	SubjectEncKey common.RawBytes
	// SubjectSignKey the public key used for signature verification.
	SubjectSignKey common.RawBytes
	// TRCVersion is the version of the issuing trc.
	TRCVersion uint64
	// Version is the certificate version. The value 0 is reserved and shall not be used.
	Version uint64
}

func PilaCertificateFromRaw(raw common.RawBytes) (*PilaCertificate, error) {
	cert := &PilaCertificate{}
	if err := json.Unmarshal(raw, cert); err != nil {
		return nil, common.NewBasicError("Unable to parse PilaCertificate", err)
	}
	if cert.Version == 0 {
		return nil, common.NewBasicError(ReservedVersion, nil)
	}
	return cert, nil
}

// Verify checks the signature of the certificate based on a trusted verifying key and the
// associated signature algorithm. Further, it verifies that the certificate belongs to the given
// subject, and that it is valid at the current time.
func (c *PilaCertificate) Verify(subject PilaCertificateEntity, verifyKey common.RawBytes, signAlgo string) error {
	if !subject.Eq(c.Subject) {
		return common.NewBasicError(InvalidSubject, nil,
			"expected", c.Subject, "actual", subject)
	}
	if err := c.VerifyTime(uint64(time.Now().Unix())); err != nil {
		return err
	}
	return c.VerifySignature(verifyKey, signAlgo)
}

// VerifyTime checks that the time ts is between issuing and expiration time. This function does
// not check the validity of the signature.
func (c *PilaCertificate) VerifyTime(ts uint64) error {
	if ts < c.IssuingTime {
		return common.NewBasicError(EarlyUsage, nil,
			"IssuingTime", util.TimeToString(util.USecsToTime(c.IssuingTime)),
			"current", util.TimeToString(util.USecsToTime(ts)))
	}
	if ts > c.ExpirationTime {
		return common.NewBasicError(Expired, nil,
			"ExpirationTime", util.TimeToString(util.USecsToTime(c.ExpirationTime)),
			"current", util.TimeToString(util.USecsToTime(ts)))
	}
	return nil
}

// VerifySignature checks the signature of the certificate based on a trusted verifying key and the
// associated signature algorithm.
func (c *PilaCertificate) VerifySignature(verifyKey common.RawBytes, signAlgo string) error {
	sigInput, err := c.sigPack()
	if err != nil {
		return common.NewBasicError(UnableSigPack, err)
	}
	return crypto.Verify(sigInput, c.Signature, verifyKey, signAlgo)
}

// Sign adds signature to the certificate. The signature is computed over the certificate
// without the signature field.
func (c *PilaCertificate) Sign(signKey common.RawBytes, signAlgo string) error {
	sigInput, err := c.sigPack()
	if err != nil {
		return err
	}
	sig, err := crypto.Sign(sigInput, signKey, signAlgo)
	if err != nil {
		return err
	}
	c.Signature = sig
	return nil
}

// sigPack creates a sorted json object of all fields, except for the signature field.
func (c *PilaCertificate) sigPack() (common.RawBytes, error) {
	if c.Version == 0 {
		return nil, common.NewBasicError(ReservedVersion, nil)
	}
	m := make(map[string]interface{})
	m["CanIssue"] = c.CanIssue
	m["Comment"] = c.Comment
	m["EncAlgorithm"] = c.EncAlgorithm
	m["ExpirationTime"] = c.ExpirationTime
	m["Issuer"] = c.Issuer
	m["IssuingTime"] = c.IssuingTime
	m["SignAlgorithm"] = c.SignAlgorithm
	m["Subject"] = c.Subject
	m["SubjectEncKey"] = c.SubjectEncKey
	m["SubjectSignKey"] = c.SubjectSignKey
	m["TRCVersion"] = c.TRCVersion
	m["Version"] = c.Version
	sigInput, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return sigInput, nil
}

func (c *PilaCertificate) Copy() *PilaCertificate {
	n := &PilaCertificate{
		CanIssue:       c.CanIssue,
		Comment:        c.Comment,
		EncAlgorithm:   c.EncAlgorithm,
		ExpirationTime: c.ExpirationTime,
		Issuer:         c.Issuer,
		IssuingTime:    c.IssuingTime,
		SignAlgorithm:  c.SignAlgorithm,
		Signature:      make(common.RawBytes, len(c.Signature)),
		Subject:        c.Subject,
		SubjectEncKey:  make(common.RawBytes, len(c.SubjectEncKey)),
		SubjectSignKey: make(common.RawBytes, len(c.SubjectSignKey)),
		TRCVersion:     c.TRCVersion,
		Version:        c.Version}
	copy(n.Signature, c.Signature)
	copy(n.SubjectEncKey, c.SubjectEncKey)
	copy(n.SubjectSignKey, c.SubjectSignKey)
	return n
}

func (c *PilaCertificate) String() string {
	return fmt.Sprintf("PilaCertificate %sv%d", c.Subject, c.Version)
}

func (c *PilaCertificate) JSON(indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(c, "", strings.Repeat(" ", 4))
	}
	return json.Marshal(c)
}

func (c *PilaCertificate) Eq(o *PilaCertificate) bool {
	return c.CanIssue == o.CanIssue &&
		c.Comment == o.Comment &&
		c.ExpirationTime == o.ExpirationTime &&
		c.IssuingTime == o.IssuingTime &&
		c.TRCVersion == o.TRCVersion &&
		c.Version == o.Version &&
		c.Issuer.Eq(o.Issuer) &&
		c.Subject.Eq(o.Subject) &&
		c.SignAlgorithm == o.SignAlgorithm &&
		c.EncAlgorithm == o.EncAlgorithm &&
		bytes.Equal(c.SubjectEncKey, o.SubjectEncKey) &&
		bytes.Equal(c.SubjectSignKey, o.SubjectSignKey) &&
		bytes.Equal(c.Signature, o.Signature)
}
