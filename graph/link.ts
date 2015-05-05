import { Graph, Node, Port } from "./graph-package";
import { Channel, EndPoint } from "../base/base-package";

type EndPointRef = { nodeID: string, portID: string };

export default class Link
{
  protected ownerGraph: Graph;
  protected _id: string;

  protected channel: Channel;
  protected from: EndPointRef;
  protected to: EndPointRef;

  protected _protocolID: string;

  protected static propertyMap = {
    protocol: "_protocolID",
    from: "from",
    to: "to",
  };

  constructor( owner: Graph, link )
  {
    this.channel = null;

    this._id = "";

    this.ownerGraph = owner;

    for( let prop in Link.propertyMap )
    {
      this[ Link.propertyMap[ prop ] ] = link[ prop ];
    }
  }

  toObject( opts?: any ): Object
  {
    let link = {
      id: this._id,
      protocol: this._protocolID,
      from: this.from,
      to: this.to
    };

    return link;
  }

  set id( id: string )
  {
    this._id = id;
  }

  connect( channel: Channel )
  {
    // identify fromPort in fromNode
    var fromPort: Port = this.fromNode.identifyPort( this.from.portID, this.protocol );

    // identify toPort in toNode
    var toPort: Port = this.toNode.identifyPort( this.to.portID, this.protocol );

    this.channel = channel;

    fromPort.connect( channel );
    toPort.connect( channel );
  }

  disconnect()
  {
    this.channel.getEndPoints().forEach( ( endPoint ) => {
      endPoint.disconnect();
    } );

    this.channel = null;
  }

  get fromNode(): Node
  {
    return this.ownerGraph.getNodeByID( this.from.nodeID );
  }

  get fromPort(): Port
  {
    var node = this.fromNode;

    return (node) ? node.getPortByID( this.from.portID ) : undefined;
  }

  set fromPort( port: Port )
  {
    this.from = {
      nodeID: port.node.id,
      portID: port.id
    };

    this._protocolID = port.protocol;
  }

  get toNode(): Node
  {
    return this.ownerGraph.getNodeByID( this.to.nodeID );
  }

  get toPort(): Port
  {
    var node = this.toNode;

    return (node) ? node.getPortByID( this.to.portID ) : undefined;
  }

  set toPort( port: Port )
  {
    this.to = {
      nodeID: port.node.id,
      portID: port.id
    };

    this._protocolID = port.protocol;
  }

  get protocol(): string
  {
    return this._protocolID;
  }
}
