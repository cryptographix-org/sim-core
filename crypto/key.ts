class Key
{
  protected id: string;
  protected keyComponents: any[];

  constructor( id: string, attributes: any )
  {
    this.id = id;
    this.keyComponents = attributes;
  }

  getComponent( componentID: string ): any
  {
    return this.keyComponents[ componentID ];
  }

  setComponent( componentID: string, value: any )
  {
    this.keyComponents[ componentID ] = value;
  }
}

export default Key;
