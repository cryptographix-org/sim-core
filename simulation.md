

Graph: Represents a graph/tree of simulation nodes, composed of Nodes and Links.
Each Node, identified by an unique ID within the Graph, also declares a set of
named communication Ports, through which it performs sends and receives data
and events. Nodes are connected via Links, which transfer data between two
(or more ) Ports.

A Graph may also declare a set of Ports, through which it sends and received
data and events. In fact, a Graph is simply a special type of Node, and any
Ports it declares are considered as public interfaces, and will be proxied
via internal Links.
