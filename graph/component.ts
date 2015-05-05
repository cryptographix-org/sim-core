type InjectType = ( string[] | ( () => string[] ) );

export default class Component
{
  static inject : InjectType;

  constructor( initialData: Object )
  {
  }

}
