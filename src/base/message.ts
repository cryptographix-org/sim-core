import { Kind } from '../base/kind';

export default class Message
{
  private header: {};
  private payload: Kind;

  constructor( header: {}, payload: Kind )
  {
    this.header = header;
    this.payload = payload;
  }

  getHeader(): Object
  {
    return this.header;
  }

  getPayload(): Kind
  {
    return this.payload;
  }
}
