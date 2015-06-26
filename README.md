# mpolsr_qualnet
Qualnet implementation of MP-OLSR

The MP-OLSR is implemented for Qualnet simulations. It is an extension of nOLSRv2. It exsits as an "add-on" in the Qualnet simulator.

About adding a new routing protocol in Qualnet, please refer to Qualnet Programmer's Guide.

MP-OLSR is an application-layer routing protocol based on OLSRv2, but it need to receive the data packet to read/modify the source routing packet header. To enable the application layer routing protocol MP-OLSR can handle the data packet, an MPOLSRRouterFunction is defined. And NetworkIpSetRouterFunction is used to register MPOLSRRouterFunction. This enables IP to directly call MPOLSRRouterFunction to determine the route for a packet if MP-OLSR is running at that interface.

Reference information:

Jiazi YI, Asmaa ADNANE, Sylvain DAVID, and Benoit PARREIN, "Multipath optimized link state routing for mobile ad hoc networks," Ad Hoc Networks, vol. 9, issue 1, Jan 2011
