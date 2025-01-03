package ndis

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/wiresock/ndisapi-go"
	"go4.org/netipx"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.NdisInboundOptions](registry, C.TypeNDIS, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx                         context.Context
	router                      adapter.ConnectionRouterEx
	logger                      log.ContextLogger
	listener                    *listener.Listener
	udpNat                      *udpnat.Service
	inboundOptions              option.InboundOptions
	localRouter                 *localRouter
	api                         *ndisapi.NdisApi
	networkManager              adapter.NetworkManager
	routeRuleSet                []adapter.RuleSet
	routeRuleSetCallback        []*list.Element[adapter.RuleSetUpdateCallback]
	routeExcludeRuleSet         []adapter.RuleSet
	routeExcludeRuleSetCallback []*list.Element[adapter.RuleSetUpdateCallback]
	routeAddressSet             []*netipx.IPSet
	routeExcludeAddressSet      []*netipx.IPSet
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NdisInboundOptions) (adapter.Inbound, error) {
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	inbound := &Inbound{
		Adapter:        inbound.NewAdapter(C.TypeNDIS, tag),
		ctx:            ctx,
		router:         router,
		logger:         logger,
		inboundOptions: options.InboundOptions,
		networkManager: networkManager,
	}
	for _, routeAddressSet := range options.RouteAddressSet {
		ruleSet, loaded := router.RuleSet(routeAddressSet)
		if !loaded {
			return nil, E.New("parse route_address_set: rule-set not found: ", routeAddressSet)
		}
		ruleSet.IncRef()
		inbound.routeRuleSet = append(inbound.routeRuleSet, ruleSet)
	}
	for _, routeExcludeAddressSet := range options.RouteExcludeAddressSet {
		ruleSet, loaded := router.RuleSet(routeExcludeAddressSet)
		if !loaded {
			return nil, E.New("parse route_exclude_address_set: rule-set not found: ", routeExcludeAddressSet)
		}
		ruleSet.IncRef()
		inbound.routeExcludeRuleSet = append(inbound.routeExcludeRuleSet, ruleSet)
	}
	api, err := ndisapi.NewNdisApi()
	if err != nil {
		return nil, E.Cause(err, "create NDIS API")
	}
	inbound.api = api
	localRouter, err := newLocalRouter(ctx, api, logger)
	if err != nil {
		return nil, E.Cause(err, "create local router")
	}
	inbound.localRouter = localRouter
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	inbound.udpNat = udpnat.New(inbound, inbound.preparePacketConnection, udpTimeout, false)
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           options.Network.Build(),
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
		PacketHandler:     inbound,
	})
	return inbound, nil
}

func (i *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	// if !i.api.IsDriverLoaded() {
	// 	return E.New("WindowsPacketFilter (NDISAPI) driver not loaded")
	// }
	err := i.listener.Start()
	if err != nil {
		return err
	}
	port := i.listener.TCPListener().Addr().(*net.TCPAddr).Port
	return i.localRouter.Start(uint16(port), "8.8.8.8")
}

func (i *Inbound) Close() error {
	if i.localRouter != nil {
		i.localRouter.Close()
	}
	if i.api != nil {
		i.api.Close()
	}
	return i.listener.Close()
}

func (i *Inbound) NewPacketEx(buffer *buf.Buffer, source M.Socksaddr) {
	var destination M.Socksaddr
	i.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, destination, nil)
}

func (i *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	metadata.Destination = M.SocksaddrFromNet(conn.RemoteAddr())
	if destinationPort, loaded := i.localRouter.tcpConnections[conn.RemoteAddr().String()]; loaded {
		metadata.Destination.Port = destinationPort
	}
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	i.logger.InfoContext(ctx, "inbound packet connection from ", source)
	i.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	var metadata adapter.InboundContext
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	//nolint:staticcheck
	metadata.InboundDetour = i.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.InboundOptions = i.listener.ListenOptions().InboundOptions
	metadata.Source = source
	metadata.Destination = destination
	if destinationPort, loaded := i.localRouter.udpEndpoints[conn.LocalAddr().String()]; loaded {
		metadata.Destination.Port = destinationPort
	}
	metadata.OriginDestination = i.listener.UDPAddr()
	i.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	return true, log.ContextWithNewID(i.ctx), &ndisPacketWriter{i.listener.PacketWriter(), source}, nil
}

type ndisPacketWriter struct {
	writer N.PacketWriter
	source M.Socksaddr
}

func (w *ndisPacketWriter) WritePacket(buffer *buf.Buffer, addr M.Socksaddr) error {
	return w.writer.WritePacket(buffer, w.source)
}
