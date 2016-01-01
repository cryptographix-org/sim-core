import { Kind } from '../base/kind';
import { EndPoint } from './end-point';

/*
* Message Header
*/
export interface MessageHeader
{
  /*
  * Message Identifier (unique) for each sent message (or CMD-RESP pair)
  */
  id?: number;

  /*
  * Message Name, indicates a command / method / response to execute
  */
  name?: string;

  /*
  * Description, useful for tracing and logging
  */
  description?: string;

  /*
  * For CMD/RESP style protocols, indicates that message dispatched
  * in response to a previous command
  */
  isResponse?: boolean;

  /*
  * EndPoint that originated the message
  */
  origin?: EndPoint;
}

/*
* A Typed Message, with header and payload
*/
export class Message<T>
{
  private _header: MessageHeader;
  private _payload: T;

  constructor( header: MessageHeader, payload: T )
  {
    this._header = header || {};
    this._payload = payload;
  }

  get header(): MessageHeader
  {
    return this._header;
  }

  get payload(): T
  {
    return this._payload;
  }
}

/*
* A typed Message whose payload is a Kind
*/
export class KindMessage<K extends Kind> extends Message<K>
{
}
