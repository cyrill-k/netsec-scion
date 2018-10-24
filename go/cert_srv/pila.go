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
	"net"

	"github.com/scionproto/scion/go/cert_srv/conf"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

type PilaHandler struct {
	conn *snet.Conn
}

func NewPilaHandler(conn *snet.Conn) *PilaHandler {
	return &PilaHandler{conn: conn}
}

// HandleReq handles endpoint certificate requests. A certificate server authenticates the client
// and grants the certificate for the given IP address if it is valid.
func (h *PilaHandler) HandleReq(a *snet.Addr, req *cert_mgmt.PilaReq, config *conf.Conf) {
	log.Info("Received PILA certificate request", "addr", a, "req", req)
	if !a.Host.IP().Equal(req.EndpointIdentifier.Host().IP()) {
		log.Info("PILA request IP address and src IP address are not identical",
			"req", req.EndpointIdentifier.Host().IP(),
			"src", a.Host.IP())
	}
	if !h.canAuthenticateIP(a.Host.IP()) {
		log.Info("Cannot authenticate IP address",
			"src", a.Host.IP())
	}
	var cert *cert.Certificate
	var err error
	if cert, err = h.createCertificate(req); err != nil {
		log.Error("Failed to create signature",
			"req", req)
	}
	if err := h.sendRep(a, cert); err != nil {
		log.Error("Failed to send reply",
			"src", a)
	}
}

func (h *PilaHandler) createCertificate(req *cert_mgmt.PilaReq) (*cert.Certificate, error) {
	return nil, nil
}

func (h *PilaHandler) canAuthenticateIP(ip net.IP) bool {
	//todo(cyrill): Adjust to the actual AS's data range
	return true
}

// sendChainRep creates a certificate chain response and sends it to the requester.
func (h *PilaHandler) sendRep(a *snet.Addr, cert *cert.Certificate) error {
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
