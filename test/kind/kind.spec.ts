import { Kind, KindBuilder, KindConstructor, FieldTypes } from 'cryptographix-sim-core';

function dumpKind( kind: Kind ) {
//  let fields = (<KindConstructor>(kind.constructor)).kindInfo.fields;
  let fields = Kind.getKindInfo( kind ).fields;

  for( let name in fields ) {
    let field = fields[name];

//  fields.forEach( ( field: FieldInfo, name: String ) => {
    let fieldType = field.fieldType;

    console.log( name + ' => ' + ( typeof fieldType ) );
    if ( fieldType == String )
      console.log( "string" );
    else if ( fieldType == Number )
      console.log( "number" );
      else if ( fieldType == FieldTypes.Integer )
        console.log( "integer" );
    else if ( fieldType == Boolean )
      console.log( "boolean" );
    else if ( fieldType == FieldTypes.Enum ) {
      console.log( "enum: " + field.enumMap.size );
      field.enumMap.forEach( (v,i) => { console.log( v + ' = ' + i ); } );
    }
    else
      console.log( fieldType.toString );

  }
}

enum Oranges {
  BLOOD,
  SEVILLE,
  SATSUMA,
  NAVEL
}

/**
* Example
*/
class FruityKind implements Kind
{
  banana: String;
  apple: Number;
  orange: Oranges;
  bit: Boolean;
  pear: Number;
}

KindBuilder.init( FruityKind, 'a Collection of fruit' )
  .stringField('banana', 'a banana' )
  .numberField('apple', 'an apple' )
  .enumField('orange', 'some sort of orange', Oranges )
  .boolField('bit', 'a bitapple' )
  .byteField('pear', 'a pear' )
  ;

describe('A Kind', () => {
  it('is an interface implemented by classes', function() {
    let fk = new FruityKind();

    console.log( Kind.getKindInfo( fk ).name );

    dumpKind( fk );

    //expect( bs.toString() ).toBe( "0001020304" );
  } );
} );
