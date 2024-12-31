package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type NdisInboundOptions struct {
	ListenOptions
	Network                NetworkList                      `json:"network,omitempty"`
	RouteAddress           badoption.Listable[netip.Prefix] `json:"route_address,omitempty"`
	RouteAddressSet        badoption.Listable[string]       `json:"route_address_set,omitempty"`
	RouteExcludeAddress    badoption.Listable[netip.Prefix] `json:"route_exclude_address,omitempty"`
	RouteExcludeAddressSet badoption.Listable[string]       `json:"route_exclude_address_set,omitempty"`
}
