// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"net"
	"time"

	"github.com/scionproto/scion/go/cert_srv/conf"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

type PilaHandler struct {
	conn *snet.Conn
	ia   addr.IA
}

func NewPilaHandler(conn *snet.Conn, ia addr.IA) *PilaHandler {
	return &PilaHandler{conn: conn, ia: ia}
}

// HandleReq handles endpoint certificate requests. A certificate server authenticates the client
// and grants the certificate for the given IP address if it is valid.
func (h *PilaHandler) HandleReq(a *snet.Addr, req *cert_mgmt.PilaReq, config *conf.Conf) {
	log.Info("Received PILA certificate request",
		"addr", a,
		"req", req)
	if !a.Host.IP().Equal(req.EndpointIdentifier.Host().IP()) {
		log.Info("PILA request IP address and src IP address are not identical",
			"req", req.EndpointIdentifier.Host().IP(),
			"src", a.Host.IP())
		return
	}
	if !h.canAuthenticateIP(a.Host.IP()) {
		log.Info("Cannot authenticate IP address",
			"src", a.Host.IP())
		return
	}
	var cert *cert.PilaCertificate
	var err error
	if cert, err = h.prepareCertificate(a, req, config); err != nil {
		log.Error("Failed to prepare signature",
			"req", req)
		return
	}

	if err := h.signCertificate(a, cert, config); err != nil {
		log.Error("Failed to sign certificate",
			"cert", cert,
			"err", err)
		return
	}

	// combine core cert, leaf cert & endpoint cert into json object
	chain, err := h.combineCertificates(a, cert, config)
	if err != nil {
		log.Error("Failed to combine certificates into single json object",
			"err", err)
		return
	}

	if err := h.sendRepPilaChain(a, chain); err != nil {
		log.Error("Failed to send reply",
			"src", a)
	}
}

func (h *PilaHandler) signCertificate(a *snet.Addr, certificate *cert.PilaCertificate, config *conf.Conf) error {
	signingKey := config.GetSigningKey()
	var chain *cert.Chain = config.Store.GetNewestChain(a.IA)
	signingAlgorithm := chain.Leaf.SignAlgorithm
	return certificate.Sign(signingKey, signingAlgorithm)
}

func (h *PilaHandler) combineCertificates(a *snet.Addr, certificate *cert.PilaCertificate, config *conf.Conf) (*cert.PilaChain, error) {
	var chain *cert.Chain = config.Store.GetNewestChain(a.IA)

	return &cert.PilaChain{
		Endpoint: certificate,
		Leaf:     chain.Leaf,
		Issuer:   chain.Issuer}, nil
}

func (h *PilaHandler) prepareCertificate(a *snet.Addr, req *cert_mgmt.PilaReq, config *conf.Conf) (*cert.PilaCertificate, error) {
	// validate req.SignedName
	validityPeriod, err := time.ParseDuration("3600s") // 1h
	if err != nil {
		return nil, errors.New("Error parsing certificate duration: " + err.Error())
	}
	issuingTime := uint64(time.Now().Unix())

	expirationTime := issuingTime + uint64(validityPeriod.Seconds())
	var signAlgorithm string
	switch req.RawPublicKey.Len() {
	case 64:
		signAlgorithm = "ECDSAP256SHA256"
	case 96:
		signAlgorithm = "ECDSAP384SHA384"
	}
	return &cert.PilaCertificate{
		CanIssue: false,
		Comment:  req.SignedName,
		// This signature does not support encryption
		//EncAlgorithm: ""
		ExpirationTime: expirationTime,
		Issuer:         a.IA,
		IssuingTime:    issuingTime,
		SignAlgorithm:  signAlgorithm,
		// set afterwards
		//Signature: nil
		Subject: cert.PilaCertificateEntity{Ipv4: req.EndpointIdentifier.Host().IP()},
		// This signature does not support encryption
		//SubjectEncKey: nil
		SubjectSignKey: req.RawPublicKey,
		TRCVersion:     h.getTRCVersion(a, config),
		Version:        1}, nil
}

func (h *PilaHandler) getTRCVersion(a *snet.Addr, config *conf.Conf) uint64 {
	return config.Store.GetNewestTRC(a.IA.I).Version
}

func (h *PilaHandler) canAuthenticateIP(ip net.IP) bool {
	//todo(cyrill): Adjust to the actual AS's data range
	return true
}

// sendChainRep creates a certificate chain response and sends it to the requester.
func (h *PilaHandler) sendRep(a *snet.Addr, cert *cert.PilaCertificate) error {
	raw, err := cert.JSON(false)
	if err != nil {
		return err
	}
	cpld, err := ctrl.NewCertMgmtPld(&cert_mgmt.PilaRep{RawCert: raw}, nil, nil)
	if err != nil {
		return err
	}
	log.Debug("Send PILA certificate reply", "cert", cert, "addr", a)
	return SendPayload(h.conn, cpld, a)
}

// sendChainRep creates a certificate chain response and sends it to the requester.
func (h *PilaHandler) sendRepPilaChain(a *snet.Addr, chain *cert.PilaChain) error {
	raw, err := chain.JSON(false)
	if err != nil {
		return err
	}
	cpld, err := ctrl.NewCertMgmtPld(&cert_mgmt.PilaRep{RawCert: raw}, nil, nil)
	if err != nil {
		return err
	}
	log.Debug("Send PILA certificate reply", "cert", chain, "addr", a)
	return SendPayload(h.conn, cpld, a)
}

// sendChainRep creates a certificate chain response and sends it to the requester.
func (h *PilaHandler) sendRepRaw(a *snet.Addr, certificates []byte) error {
	cpld, err := ctrl.NewCertMgmtPld(&cert_mgmt.PilaRep{RawCert: certificates}, nil, nil)
	if err != nil {
		return err
	}
	log.Debug("Send PILA certificate reply", "addr", a)
	return SendPayload(h.conn, cpld, a)
}
