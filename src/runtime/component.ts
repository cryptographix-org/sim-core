import { EndPointCollection, Direction } from '../messaging/end-point';
import { Protocol } from '../messaging/protocol';
import { Kind } from '../base/kind';

///
/// @class KindHelper
///
/// Builder for 'Component' metadata
export class ComponentBuilder
{
  private componentInfo: ComponentInfo;

  public init( name: string, description: string ): ComponentBuilder
  {
    this.componentInfo = {
      name: name,
      description: description,
      ports: {}
    };

    return this;
  }

  public port( id: string, direction: Direction, opts?: { protocol?: Protocol<any>; maxIndex?: number; required?: boolean } ): ComponentBuilder
  {
    opts = opts || {};

    this.componentInfo.ports[ id ] = {
      direction: direction,
      protocol: opts.protocol,
      maxIndex: opts.maxIndex,
      required: opts.required
    };

    return this;
  }

  install( ctor: ComponentConstructor ): ComponentInfo
  {
    let info = this.componentInfo;

    this.componentInfo = new ComponentInfo();

    ctor.componentInfo = info;

    return info;
  }
}

/**
* @class PortInfo
*
* Metadata about a component's Port
*/
export class PortInfo
{
  /**
  * Direction: IN, OUT, or INOUT
  *   for client-server, OUT=Client, IN=Server
  *   for socket
  */
  direction: Direction;

  protocol: Protocol<any>;

  maxIndex: number = 0;

  required: boolean = false;
}

/**
* @class ComponentInfo
*
* Metadata about a Component
*/
export class ComponentInfo
{
  static $builder = new ComponentBuilder();

  /**
  * Component Name
  */
  name: string;

  /**
  * Description for the component, to appear in 'hint'
  */
  description: string;

  /**
  * Array of Port descriptors. When active, the component will communicate
  * through corresponding EndPoints
  */
  ports: { [id: string]: PortInfo; } = {};

  constructor()
  {
    this.ports = {};
  }
}

export interface Component
{
  componentInfo?: ComponentInfo;

  onCreate?( initialData: Kind );
  onDestroy?();

  onStart?( endPoints: EndPointCollection );
  onStop?();
}

export interface ComponentConstructor
{
  new ( ...args ): Component;

  componentInfo?: ComponentInfo;
}

class C implements Component {

}

ComponentInfo.$builder.install( C );
