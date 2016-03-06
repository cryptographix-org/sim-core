import { EndPointCollection, Direction } from '../messaging/end-point';
import { Protocol } from '../messaging/protocol';

/**
* @class PortInfo
*
* Metadata about a component's Port
*/
export class PortInfo
{
  /**
  * Brief description for the port, to appear in 'hint'
  */
  description: string;

  /**
  * Direction: IN, OUT, or INOUT
  *   for client-server, OUT=Client, IN=Server
  */
  direction: Direction;

  /**
  * Protocol implemented by the port
  */
  protocol: Protocol<any>;

  /**
  * RFU - indexable ports
  */
  count: number = 0;

  /**
  * true is port must be connected for component to execute
  */
  required: boolean = false;
}
