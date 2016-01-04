import { ComponentFactory} from './component-factory';
import { Component } from './component';

import { Container } from '../dependency-injection/container';

/**
* The runtime context information for a Component instance
*/
export class ComponentContext
{
  /**
  * The component id / address
  */
  id: string;

  /**
  * The runtime component instance that this node represents
  */
  instance: Component;

  /**
  * The runtime component instance that this node represents
  */
  container: Container;

  /**
  * The component factory that created us
  */
  factory: ComponentFactory;

  constructor( factory: ComponentFactory, id: string ) {
    this.id = id;
    this.factory = factory;
    this.container = factory.container.createChild();
  }

  /**
  * Set the loaded component instance
  */
  componentLoaded( instance: Component ) {
    this.instance = instance;

    instance;
  }

  get component(): Component {
    return this.instance;
  }

  load( ): Promise<void>
  {
    let me = this;

    this.instance = null;

    return new Promise<void>( (resolve, reject) => {
      if ( !this.id || this.id == "" )
        resolve();
      else {
        this.factory.loadComponent( this.id )
          .then( (instance) => {
              me.instance = instance;
              resolve();
          })
          .catch( (err) => {
            reject( err );
          });
        }
    } );
  }



}
