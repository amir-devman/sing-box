package ndis

import (
	"context"
	"net/netip"
	"strings"
	"sync"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/wiresock/ndisapi-go"
	"github.com/wiresock/ndisapi-go/driver"
	"github.com/wiresock/ndisapi-go/netlib"
)

type localRouter struct {
	api            *ndisapi.NdisApi
	ctx            context.Context
	tcpConnections map[string]uint16
	udpEndpoints   map[string]uint16
	tcpMutex       sync.RWMutex
	udpMutex       sync.RWMutex
	localPort      uint16
	filter         *driver.QueuedPacketFilter
	processLookup  *netlib.ProcessLookup
}

func newLocalRouter(ctx context.Context, api *ndisapi.NdisApi) (*localRouter, error) {
	adapters, err := api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return nil, E.Cause(err, "get TCP/IP bound adapters info")
	}
	localRouter := &localRouter{
		api:            api,
		ctx:            ctx,
		tcpConnections: make(map[string]uint16),
		udpEndpoints:   make(map[string]uint16),
		processLookup:  &netlib.ProcessLookup{},
	}
	filter, err := driver.NewQueuedPacketFilter(api, adapters, nil, func(handle ndisapi.Handle, packet *ndisapi.IntermediateBuffer) ndisapi.FilterAction {
		if len(packet.Buffer) < header.EthernetMinimumSize {
			return ndisapi.FilterActionPass
		}
		ether := header.Ethernet(packet.Buffer[:header.EthernetMinimumSize])

		ipv4 := header.IPv4(packet.Buffer[header.EthernetMinimumSize : packet.Length-header.EthernetMinimumSize])
		if ipv4.IsValid(int(packet.Length - header.EthernetMinimumSize)) {
			switch ipv4.TransportProtocol() {
			case tcpip.TransportProtocolNumber(header.TCPProtocolNumber):
				tcpOffset := header.EthernetMinimumSize + ipv4.HeaderLength()
				tcp := header.TCP(packet.Buffer[tcpOffset : tcpOffset+header.TCPMinimumSize])

				src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ipv4.SourceAddress().As4())), tcp.SourcePort())
				dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ipv4.DestinationAddress().As4())), tcp.DestinationPort())

				redirect := false
				connName := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ipv4.DestinationAddress().As4())), tcp.SourcePort()).String()

				if (tcp.Flags() & (header.TCPFlagSyn | header.TCPFlagAck)) == header.TCPFlagSyn {
					processInfo, err := localRouter.processLookup.FindProcessInfo(ctx, false, src, dst, false)
					if err == nil && strings.Contains(processInfo.PathName, "sing-box") {
						return ndisapi.FilterActionPass
					}

					localRouter.tcpMutex.Lock()
					if _, loaded := localRouter.tcpConnections[connName]; !loaded {
						localRouter.tcpConnections[connName] = tcp.DestinationPort()
					}
					localRouter.tcpMutex.Unlock()

					redirect = true
				} else {
					localRouter.tcpMutex.RLock()
					_, exists := localRouter.tcpConnections[connName]
					localRouter.tcpMutex.RUnlock()

					if exists {
						if tcp.Flags()&(header.TCPFlagRst|header.TCPFlagFin) != 0 {
							localRouter.tcpMutex.Lock()
							delete(localRouter.tcpConnections, connName)
							localRouter.tcpMutex.Unlock()

						}

						redirect = true
					}
				}

				if redirect {
					// Swap source and destination MAC addresses
					ethernetFields := &header.EthernetFields{
						SrcAddr: ether.DestinationAddress(),
						DstAddr: ether.SourceAddress(),
						Type:    ether.Type(),
					}
					ether.Encode(ethernetFields)

					// Swap source and destination IP addresses
					dstAddr := ipv4.DestinationAddress()
					srcAddr := ipv4.SourceAddress()
					ipv4.SetSourceAddressWithChecksumUpdate(dstAddr)
					ipv4.SetDestinationAddressWithChecksumUpdate(srcAddr)
					tcp.SetDestinationPortWithChecksumUpdate(localRouter.localPort)

					// Copy Ethernet, IPv4, and TCP layers into buffer after the change
					copy(packet.Buffer[0:header.EthernetMinimumSize], ether)
					copy(packet.Buffer[header.EthernetMinimumSize:], ipv4)
					copy(packet.Buffer[tcpOffset:], tcp)

					return ndisapi.FilterActionRedirect
				} else if localRouter.localPort == tcp.SourcePort() {
					connName := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ipv4.DestinationAddress().As4())), uint16(tcp.DestinationPort())).String()

					localRouter.tcpMutex.Lock()
					it, exists := localRouter.tcpConnections[connName]
					if !exists {
						localRouter.tcpMutex.Unlock()
						return ndisapi.FilterActionPass
					}

					if tcp.Flags()&(header.TCPFlagRst|header.TCPFlagFin) != 0 {
						delete(localRouter.tcpConnections, connName)
					}
					localRouter.tcpMutex.Unlock()

					// Redirect the packet back to the original destination
					tcp.SetSourcePortWithChecksumUpdate(it)
					// Swap source and destination MAC addresses
					ethernetFields := &header.EthernetFields{
						SrcAddr: ether.DestinationAddress(),
						DstAddr: ether.SourceAddress(),
						Type:    ether.Type(),
					}
					ether.Encode(ethernetFields)

					// Swap source and destination IP addresses
					dstAddr := ipv4.DestinationAddress()
					srcAddr := ipv4.SourceAddress()
					ipv4.SetSourceAddressWithChecksumUpdate(dstAddr)
					ipv4.SetDestinationAddressWithChecksumUpdate(srcAddr)

					// Copy Ethernet, IPv4, and TCP layers into buffer after the change
					copy(packet.Buffer[0:header.EthernetMinimumSize], ether)
					copy(packet.Buffer[header.EthernetMinimumSize:], ipv4)
					copy(packet.Buffer[tcpOffset:], tcp)

					return ndisapi.FilterActionRedirect
				}
			}
		}

		return ndisapi.FilterActionPass
	})
	if err != nil {
		return nil, E.Cause(err, "create queued packet filter")
	}
	localRouter.filter = filter
	return localRouter, nil
}

func (l *localRouter) Close() error {
	l.Stop()
	return nil
}

func (l *localRouter) Start(port uint16) error {
	l.localPort = port
	if err := l.filter.StartFilter(9); err != nil {
		return E.Cause(err, "start filter")
	}
	return nil
}

func (l *localRouter) Stop() error {
	err := l.filter.StopFilter()
	if err != nil {
		return E.Cause(err, "stop filter")
	}
	return nil
}
