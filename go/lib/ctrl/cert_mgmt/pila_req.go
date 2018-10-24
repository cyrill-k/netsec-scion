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

// This file contains the Go representation of PILA certificate requests.

package cert_mgmt

import (
	"encoding/base64"
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*PilaReq)(nil)

type HostInfo struct {
	Port  uint16
	Addrs struct {
		Ipv4 []byte
		Ipv6 []byte
	}
}

func (h *HostInfo) Host() addr.HostAddr {
	if len(h.Addrs.Ipv4) > 0 {
		return addr.HostIPv4(h.Addrs.Ipv4)
	}
	if len(h.Addrs.Ipv6) > 0 {
		return addr.HostIPv6(h.Addrs.Ipv6)
	}
	return nil
}

type PilaReq struct {
	SignedName         string
	EndpointIdentifier HostInfo
	RawPublicKey       common.RawBytes `capnp:"publicKey"`
}

func (c *PilaReq) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(c.RawPublicKey)
}

func (c *PilaReq) ProtoId() proto.ProtoIdType {
	return proto.PilaCertReq_TypeID
}

func (c *PilaReq) String() string {
	return fmt.Sprintf("SignedName: %s, Endpointidentifier: %v, PublicKey: %s", c.SignedName, c.EndpointIdentifier, c.PublicKeyBase64())
}
