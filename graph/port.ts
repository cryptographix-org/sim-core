import EndPoint from "../base/end-point";
import { Direction } from "../base/end-point"
import Node from './node';

export default class Port extends EndPoint
{
  protected ownerNode: Node;
  protected _id: string;
  protected _protocolID: string;

  constructor( owner: Node, attributes: any )
  {
    super( attributes.direction || Direction.INOUT );

    this.ownerNode = owner;
  }

  toObject( opts?: any ): Object
  {
    var port = {

    };

    return port;
  }

  get id(): string
  {
    return this._id;
  }
  set id( id: string )
  {
    this._id = id;
  }

  get node(): Node
  {
    return this.ownerNode;
  }

  get protocol(): string
  {
    return this._protocolID;
  }
}
