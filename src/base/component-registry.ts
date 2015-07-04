import { EndPoints } from './end-point';
import { ComponentInterface, InjectType } from './component-interface';

export class Component implements ComponentInterface
{
  static $inject : InjectType;

  onCreate( initialData: Object )
  {

  }

  onDestroy()
  {

  }

  onStart( endPoints: EndPoints )
  {

  }

  onPause()
  {

  }

  onResume()
  {

  }

  onStop()
  {

  }
}
export type ComponentType = typeof Component;

export class ComponentRegistry
{
//  components: ComponentType[];
  components: ComponentInterface[];

  constructor()
  {
    this.components = [];
  }

  setComponent( name: string, comp: ComponentInterface )
  {
    this.components[ name ] = comp;
  }

  getComponent( name: string ): ComponentType
  {
    return this.components[ name ];
  }

  protected loadComponent( name: string ): Promise<ComponentType>
  {
    return new Promise<ComponentType>( (resolve, reject) => {
      resolve( this.getComponent[ name ] );
    });
  }

  getComponentInstance( name: string, initialData: Object ): Promise<Component>
  {
    let createComponent = function( componentType: ComponentType )
    {
      let newInstance: Component = null;
      let injects: string[] = [];

      if ( componentType.$inject instanceof Array )
        injects = <string[]>componentType.$inject;
      else if ( typeof componentType.$inject == "function" )
        injects = ( <()=>string[]> componentType.$inject )();

      if ( injects && injects.length > 0 )
        ;

      newInstance = new componentType( );
      if ( newInstance.onCreate )
        newInstance.onCreate( initialData );

      return newInstance;
    }

    let componentType: ComponentType = this.getComponent( name );

    if ( componentType )
    {
      return new Promise<Component>( (resolve, reject) => {
        resolve( createComponent( componentType ) );
      });
    }

    return new Promise<Component>( (resolve, reject) => {
      this.loadComponent( name )
            .then( (componentType)=> {
              resolve( createComponent( componentType ) );
            } );
    });
  }
}
