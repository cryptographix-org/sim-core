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

  public init( name: string, description: string, category?: string ): ComponentBuilder
  {
    this.componentInfo = {
      name: name,
      description: description,
      detailLink: '',
      category: category,
      author: '',
      ports: {},
      stores: {}
    };

    return this;
  }

  public port( id: string, direction: Direction, opts?: { protocol?: Protocol<any>; index?: number; required?: boolean } ): ComponentBuilder
  {
    opts = opts || {};

    this.componentInfo.ports[ id ] = {
      direction: direction,
      protocol: opts.protocol,
      index: opts.index,
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

  index: number = 0;

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
  * Brief description for the component, to appear in 'hint'
  */
  description: string;

  /**
  * Link to detailed information for the component
  */
  detailLink: string = '';

  /**
  * Category name for the component, groups same categories together
  */
  category: string = '';

  /**
  * Author's name
  */
  author: string = '';

  /**
  * Array of Port descriptors. When active, the component will communicate
  * through corresponding EndPoints
  */
  ports: { [id: string]: PortInfo } = {};
  stores: { [id: string]: PortInfo } = {};

  constructor()
  {
//    this.ports = {};
//    this.stores = {};
  }
}

export interface Component
{
  componentInfo?: ComponentInfo;

  setup?( initialData: Kind ): EndPointCollection;
  teardown?();

  start?();
  stop?();

  pause?();
  resume?();
}

export interface ComponentConstructor
{
  new ( ...args ): Component;

  componentInfo?: ComponentInfo;
}

class C implements Component {

}

ComponentInfo.$builder.install( C );
