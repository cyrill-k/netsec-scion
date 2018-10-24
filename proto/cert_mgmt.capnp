@0xec3b2b10a5e23975;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

using Sciond = import "sciond.capnp";

struct CertChainReq {
    isdas @0 :UInt64;
    version @1 :UInt64;
    cacheOnly @2 :Bool;
}

struct CertChain {
    chain @0 :Data;
}

struct CertChainIssReq {
    cert @0 :Data;        # Raw Certificate with desired values
}

struct CertChainIssRep {
    chain @0 :Data;
}

struct TRCReq {
    isd @0 :UInt16;
    version @1 :UInt64;
    cacheOnly @2 :Bool;
}

struct TRC {
    trc @0 :Data;
}

struct PilaCertReq {
    signedName @0 :Text;
    endpointIdentifier @1 :Sciond.HostInfo;
    publicKey @2 :Data;
}

struct PilaCertRep {
    cert @0 :Data;
}

struct CertMgmt {
    union {
        unset @0 :Void;
        certChainReq @1 :CertChainReq;
        certChain @2 :CertChain;
        trcReq @3 :TRCReq;
        trc @4 :TRC;
        certChainIssReq @5 :CertChainIssReq;
        certChainIssRep @6 :CertChainIssRep;
        pilaCertReq @7 :PilaCertReq;
        pilaCertRep @8 :PilaCertRep;
    }
}
