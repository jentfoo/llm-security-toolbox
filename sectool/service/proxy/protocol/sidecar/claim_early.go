package sidecar

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// portMin and portMax bound a normalized claim range; an unset wire range spans both.
const (
	portMin = 1
	portMax = 65535
)

// earlyClaim is the compiled form of a wire early_claim, shared by runtime matching
// and registration conflict analysis so the two cannot diverge.
type earlyClaim struct {
	ports     wire.PortRange
	prefix    []byte
	hostMatch string
	sniMatch  string
	terminate bool
	cert      *types.CertSpec
	probe     bool
	probeMax  int
}

// compileEarlyClaims compiles a registration's early claims, returning an error
// naming the first claim that can never match.
func compileEarlyClaims(claims []wire.EarlyClaim) ([]earlyClaim, error) {
	out := make([]earlyClaim, len(claims))
	for i := range claims {
		c, err := compileEarlyClaim(&claims[i])
		if err != nil {
			return nil, fmt.Errorf("early_claim[%d]: %w", i, err)
		}
		out[i] = c
	}
	return out, nil
}

func compileEarlyClaim(ec *wire.EarlyClaim) (earlyClaim, error) {
	out := earlyClaim{
		ports:     ec.PortRange,
		hostMatch: ec.HostMatch,
		probe:     ec.Probe,
		probeMax:  ec.ProbeMaxBytes,
	}
	if ec.PortRange.Low == 0 && ec.PortRange.High == 0 {
		out.ports = wire.PortRange{Low: portMin, High: portMax}
	} else if ec.PortRange.Low < portMin || ec.PortRange.High > portMax || ec.PortRange.Low > ec.PortRange.High {
		return earlyClaim{}, fmt.Errorf("invalid port_range %d-%d", ec.PortRange.Low, ec.PortRange.High)
	}
	if ec.ProbeMaxBytes < 0 {
		return earlyClaim{}, errors.New("probe_max_bytes must not be negative")
	}
	if ec.MagicBytesPrefix != "" {
		prefix, err := base64.StdEncoding.DecodeString(ec.MagicBytesPrefix)
		if err != nil || len(prefix) == 0 {
			return earlyClaim{}, errors.New("magic_bytes_prefix must be non-empty standard base64")
		}
		out.prefix = prefix
	}
	if ec.TLS != nil {
		out.terminate, out.sniMatch = ec.TLS.Terminate, ec.TLS.SNIMatch
		out.cert = compileCertSpec(ec.TLS.Cert)
	}
	return out, nil
}

// compileCertSpec converts a claim's additive SAN declaration, dropping unparsable
// entries and returning nil when nothing is added.
func compileCertSpec(c *wire.TLSCertSpec) *types.CertSpec {
	if c == nil {
		return nil
	}
	spec := &types.CertSpec{
		DNSNames:   c.DNSNames,
		Emails:     c.Emails,
		CommonName: c.CommonName,
	}
	for _, s := range c.IPAddresses {
		if ip := net.ParseIP(s); ip != nil {
			spec.IPAddresses = append(spec.IPAddresses, ip)
		}
	}
	for _, s := range c.URIs {
		if u, err := url.Parse(s); err == nil {
			spec.URIs = append(spec.URIs, u)
		}
	}
	if spec.Empty() {
		return nil
	}
	return spec
}

// matchPort reports whether p falls in the claim's range.
func (e *earlyClaim) matchPort(p int) bool { return p >= e.ports.Low && p <= e.ports.High }

// matchTLS reports whether the claim gates TLS termination for this connection.
func (e *earlyClaim) matchTLS(sni, host string, port int) bool {
	return e.terminate && e.matchPort(port) &&
		(e.sniMatch == "" || e.sniMatch == sni) &&
		(e.hostMatch == "" || e.hostMatch == host)
}

// matchScope reports whether the claim's declared scope covers the offered stream.
// Magic bytes and probe are evaluated separately by the caller.
func (e *earlyClaim) matchScope(c *protocol.EarlyClaimCtx) bool {
	if !c.TLSTerminated {
		var port int
		if a, ok := c.ClientConn.LocalAddr().(*net.TCPAddr); ok {
			port = a.Port
		}
		return e.matchPort(port)
	}
	// post-CONNECT: the range gates the destination the client asked for
	var host string
	var port int
	if c.Target != nil {
		host, port = c.Target.Hostname, c.Target.Port
	}
	if !e.matchPort(port) || (e.hostMatch != "" && e.hostMatch != host) {
		return false
	}
	return !e.terminate || e.sniMatch == "" || e.sniMatch == c.SNI
}

// blanketOnPort reports whether the claim would swallow every connection reaching
// the native proxy port, leaving the proxy unusable.
func (e *earlyClaim) blanketOnPort(port int) bool {
	return port != 0 && !e.terminate && !e.probe && len(e.prefix) == 0 && e.matchPort(port)
}

// earlyClaimConflict reports whether two early claims overlap on port range with no
// distinguishing matcher.
func earlyClaimConflict(a, b *earlyClaim) bool {
	if a.ports.Low > b.ports.High || b.ports.Low > a.ports.High {
		return false
	}
	return !earlyClaimsDistinct(a, b)
}

// earlyClaimsDistinct reports whether two overlapping-range early claims are
// distinguished by a non-overlapping matcher.
func earlyClaimsDistinct(a, b *earlyClaim) bool {
	if a.terminate != b.terminate {
		return true // separate seams: a terminating claim is offered the stream first
	} else if a.probe || b.probe {
		return a.probe && b.probe // both probe may chain; mixed probe/static is ambiguous
	} else if len(a.prefix) > 0 && len(b.prefix) > 0 &&
		!bytes.HasPrefix(a.prefix, b.prefix) && !bytes.HasPrefix(b.prefix, a.prefix) {
		return true
	}
	return a.terminate && a.sniMatch != "" && b.sniMatch != "" && a.sniMatch != b.sniMatch
}
