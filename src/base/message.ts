import { Kind } from './kind';

export class Message
{
  private _header: {};
  private _payload: Kind;

  constructor( header: {}, payload: Kind )
  {
    this._header = header;
    this._payload = payload;
  }

  get header(): Object
  {
    return this._header;
  }

  get payload(): Kind
  {
    return this._payload;
  }
}
