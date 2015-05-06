import Component from "./component";

type ComponentType = typeof Component;

export default class ComponentRegistry
{
  components: ComponentType[];

  constructor()
  {
    this.components = [];
  }

  setComponent( name: string, comp: ComponentType )
  {
    this.components[ name ] = comp;
  }

  getComponent( name: string ): ComponentType
  {
    return this.components[ name ];
  }

  protected loadComponent( name: string ): Promise<Component>
  {
    return new Promise<Component>( (resolve, reject) => {
      resolve( this.getComponent[ name ] );
    });
  }

  getComponentInstance( name: string, initialData: Object ): Promise<Component>
  {
    let componentType: ComponentType = this.getComponent( name );

    if ( componentType )
    {
      return new Promise<Component>( (resolve, reject) => {
        let newInstance: Component = null;
        let injects: string[] = [];

        if ( componentType.inject instanceof Array )
          injects = <string[]>componentType.inject;
        else if ( typeof componentType.inject == "function" )
          injects = ( <()=>string[]> componentType.inject )();

        if ( injects && injects.length > 0 )
          ;

        newInstance = new componentType( initialData );

        resolve( newInstance );
      });
    }

    return new Promise<Component>( (resolve, reject) => {
      this.loadComponent( name )
      .then( (comp)=> {
        resolve( new Component( initialData ) );
      } );
    });
  }
}
