package ndis

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/wiresock/ndisapi-go"
	"github.com/wiresock/ndisapi-go/driver"
	"github.com/wiresock/ndisapi-go/netlib"
	"golang.org/x/sys/windows"
)

type localRouter struct {
	sync.Mutex
	api            *ndisapi.NdisApi
	ctx            context.Context
	logger         log.ContextLogger
	tcpConnections map[string]uint16
	udpEndpoints   map[string]uint16
	tcpMutex       sync.RWMutex
	udpMutex       sync.RWMutex
	localPort      uint16
	filter         *driver.QueuedPacketFilter
	ifNotifyHandle windows.Handle
	ifIndex        int // Index of the network interface used.
	adapters       *ndisapi.TcpAdapterList
	defaultAdapter *netlib.NetworkAdapterInfo
	processLookup  *netlib.ProcessLookup
	pid            int // current process pid
	routeCheckIP   string
	active         bool
}

func newLocalRouter(ctx context.Context, api *ndisapi.NdisApi, logger log.ContextLogger) (*localRouter, error) {
	adapters, err := api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return nil, E.Cause(err, "get TCP/IP bound adapters info")
	}

	localRouter := &localRouter{
		api:            api,
		ctx:            ctx,
		logger:         logger,
		tcpConnections: make(map[string]uint16),
		udpEndpoints:   make(map[string]uint16),
		processLookup:  &netlib.ProcessLookup{},
		adapters:       adapters,
		pid:            os.Getpid(),
		active:         false,
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

func (l *localRouter) Start(port uint16, routeCheckIP string) error {
	l.Lock()
	defer l.Unlock()

	if l.active {
		return E.New("ndis local router is already active")
	}
	l.localPort = port

	if l.updateNetworkConfiguration(routeCheckIP) {
		if err := l.filter.StartFilter(int(l.ifIndex)); err != nil {
			return E.Cause(err, "start filter")
		}
		l.logger.DebugContext(l.ctx, "Filter engine has been started using adapter: ", l.defaultAdapter.Name)
	}

	// Register for network interface change notifications
	handle, err := netlib.NotifyIpInterfaceChange(l.ipInterfaceChangedCallback, 0, true)
	if err != nil {
		l.logger.ErrorContext(l.ctx, "ndis local_router NotifyIpInterfaceChange failed")
	} else {
		l.ifNotifyHandle = handle
	}

	l.active = true
	return nil
}

func (l *localRouter) Stop() error {
	l.Lock()
	defer l.Unlock()

	// Cancel network interface change notifications
	if err := netlib.CancelMibChangeNotify2(l.ifNotifyHandle); err != nil {
		return E.Cause(err, "CancelMibChangeNotify2 failed")
	}
	windows.CloseHandle(l.ifNotifyHandle)
	l.filter.StopFilter()
	l.active = false
	return nil
}

// updateNetworkConfiguration updates the network configuration based on the current state of the IP interfaces.
func (l *localRouter) updateNetworkConfiguration(routeCheckIP string) bool {
	// Attempts to reconfigure the filter. If it fails, logs an error.
	if err := l.filter.Reconfigure(); err != nil {
		l.logger.ErrorContext(l.ctx, E.Cause(err, "failed to update WinpkFilter network interfaces"))
	}

	adapterInfo, adapters, err := netlib.GetNetworkAdapterInfo(l.api)
	if err != nil {
		l.logger.ErrorContext(l.ctx, E.Cause(err, "failed to get network adapter info"))
		return false
	}
	l.adapters = adapters
	selectedAdapter := adapterInfo[0]
	l.routeCheckIP = routeCheckIP

	defaultAdapter, err := netlib.GetBestInterface(adapterInfo, routeCheckIP)
	if err != nil {
		l.logger.ErrorContext(l.ctx, fmt.Sprintf("Failed to find best network adapter: %v\n Using very first adapter: %s", err, selectedAdapter.Name))
	} else {
		selectedAdapter = defaultAdapter

		l.logger.InfoContext(l.ctx, "Detected default interface: ", defaultAdapter.Name)
	}

	l.ifIndex = selectedAdapter.AdapterIndex
	l.defaultAdapter = selectedAdapter

	return true
}

// This is a callback function to handle changes in the IP interface, typically invoked when there are network changes.
func (l *localRouter) ipInterfaceChangedCallback(callerContext uintptr, row *windows.MibIpInterfaceRow, notificationType netlib.MibNotificationType) uintptr {
	adapterInfo, adapters, err := netlib.GetNetworkAdapterInfo(l.api)
	if err != nil {
		l.logger.ErrorContext(l.ctx, "Failed to get network adapter info: %v", err)
	}
	l.adapters = adapters

	defaultAdapter, err := netlib.GetBestInterface(adapterInfo, l.routeCheckIP)
	if err != nil {
		l.logger.ErrorContext(l.ctx, E.Cause(err, "IP Interface changed: no internet available"))
		return 0
	}

	selectedAdapter := defaultAdapter
	if selectedAdapter.AdapterIndex == l.ifIndex {
		// nothing has changed
		return 0
	}

	l.ifIndex = selectedAdapter.AdapterIndex
	l.defaultAdapter = selectedAdapter

	go func() {
		l.filter.StopFilter()
		if l.updateNetworkConfiguration(l.routeCheckIP) {
			l.filter.StartFilter(int(l.ifIndex))
		}
	}()

	return 0
}
