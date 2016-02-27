import { ByteArray } from './byte-array';

export class Enum {
}

export class Integer extends Number {
}

/**
 * Set of data types that are valid as Kind fields
 * includes FieldTypeArray kludge required for TS to parse recursive
 * type definitions
 */

export interface FieldArray extends Array<FieldType> {}
export type FieldType = String | Number | Integer | Enum | ByteArray | Kind | FieldArray;

export class FieldArray implements FieldArray {}

export var FieldTypes = {
  Boolean: Boolean,

  Number: Number,

  Integer: Integer,

  ByteArray: ByteArray,

  Enum: Enum,

  Array: FieldArray,

  String: String,

  Kind: Kind
}

export interface FieldOptions {
  /**
  * minimum length for String, minimum value for Number/Integer
  */
  minimum?: number;

  /**
  * maximum length for String, maximum value for Number/Integer
  */
  maximum?: number;

  /**
  * default value during initialization
  */
  "default"?: any;

  /**
  * does not exist as an ownProperty
  */
  calculated?: boolean;

  /**
  * sub-kind, when field is type Kind
  */
  kind?: Kind;

  /**
  * sub-field info, when field is type FieldArray
  */
  arrayInfo?: FieldInfo;

  /**
  * index/value map, when field if type Enum
  */
  enumMap?: Map<number, string>;
}

export interface FieldInfo extends FieldOptions {
  /**
  * Description for field
  */
  description: string;

  /**
  * Type of field, one of FieldTypes
  */
  fieldType: FieldType;
}


/**
* Metadata about a Kind. Contains name, description and a map of
* property-descriptors that describe the serializable fields of
* an object of that Kind.
*/
export class KindInfo
{
  name: string;

  description: string;

  fields: { [id: string]: FieldInfo } = {};
}

/**
* Builder for 'Kind' metadata
*/
export class KindBuilder
{
  private ctor: KindConstructor;

  constructor( ctor: KindConstructor, description: string ) {
    this.ctor = ctor;

    ctor.kindInfo = {
      name: ctor.name,
      description: description,
      fields: {}
    }
  }


  private kindInfo: KindInfo;

  public static init( ctor: KindConstructor, description: string ): KindBuilder
  {
    let builder = new KindBuilder( ctor, description );

    return builder;
  }

  public field( name: string, description: string, fieldType: FieldType, opts: FieldOptions = {} ): KindBuilder
  {
    let field: FieldInfo = <FieldInfo>opts;

    field.description = description;
    field.fieldType = fieldType;

    this.ctor.kindInfo.fields[ name ] = field;

    return this;
  }

  public boolField( name: string, description: string, opts: FieldOptions = {} ): KindBuilder {
    return this.field( name, description, Boolean, opts );
  }

  public numberField( name: string, description: string, opts: FieldOptions = {} ): KindBuilder {
    return this.field( name, description, Number, opts );
  }

  public integerField( name: string, description: string, opts: FieldOptions = {} ): KindBuilder {
    return this.field( name, description, Integer, opts );
  }

  public uint32Field( name: string, description: string, opts: FieldOptions = {} ): KindBuilder {
    opts.minimum = opts.minimum || 0;
    opts.maximum = opts.maximum || 0xFFFFFFFF;

    return this.field( name, description, Integer, opts );
  }

  public byteField( name: string, description: string, opts: FieldOptions = {} ): KindBuilder {
    opts.minimum = opts.minimum || 0;
    opts.maximum = opts.maximum || 255;

    return this.field( name, description, Integer, opts );
  }

  public stringField( name: string, description: string, opts: FieldOptions = {} ): KindBuilder {
    return this.field( name, description, String, opts );
  }

  public kindField( name: string, description: string, kind: Kind, opts: FieldOptions = {} ): KindBuilder {
    opts.kind = kind;

    return this.field( name, description, Kind, opts );
  }

  public enumField( name: string, description: string, enumm: { [ idx: number ]: string }, opts: FieldOptions = {} ): KindBuilder {

    opts.enumMap = new Map<number,string>( );

    for( let idx in enumm ) {
      if ( 1 * idx == idx )
        opts.enumMap.set( idx, enumm[ idx ] );
    }

    return this.field( name, description, Enum, opts );
  }
}

/*  makeKind( kindConstructor, kindOptions )
  {
    var $kindInfo = kindOptions.kindInfo;

    kindConstructor.$kindName = $kindInfo.title;

    var keys = Object.keys( kindOptions.kindMethods );

    for ( var j = 0, jj = keys.length; j < jj; j++ ) {
      var key = keys[j];
      kindConstructor[key] = kindOptions.kindMethods[key];
    }

    kindConstructor.getKindInfo = kindConstructor.prototype.getKindInfo = function getKindInfo() {
      return $kindInfo;
    }

    return kindConstructor;
  }
*/

/**
* Represents a serializable and inspectable data-type
* implemented as a hash-map containing key-value pairs,
* along with metadata that describes each field using a json-scheme like
*/
export interface Kind
{
}

export class Kind implements Kind {
  static getKindInfo( kind: Kind ): KindInfo {
    return (<KindConstructor>(kind.constructor)).kindInfo;
  }

  static initFields( kind: Kind, attributes: {} = {}  ) {
    let kindInfo = Kind.getKindInfo( kind );

    for( let id in kindInfo.fields ) {
      let field = kindInfo.fields[ id ];
      let fieldType = field.fieldType;

//      console.log( id + ':' + fieldType );
//      console.log( kind.hasOwnProperty(id)  );

      let val: any;

      if ( !field.calculated ) {
        // we only set 'non'-calculated field, since calculated field have
        // no setter

        // got a value for this field ?
        if ( attributes[ id ] )
          val = attributes[ id ];
        else if ( field.default != undefined )
          val = field.default;
        else if ( fieldType == String )
          val = '';
        else if ( fieldType == Number )
          val = 0;
        else if ( fieldType == Integer )
          val = field.minimum || 0;
        else if ( fieldType == Boolean )
          val = false;
        else if ( fieldType == ByteArray )
          val = new ByteArray();
        else if ( fieldType == Enum )
          val = field.enumMap.keys[0];
        else if ( fieldType == Kind ) {
          let xx = (<Kind>fieldType).constructor;
          val = Object.create( xx );
        }

        kind[ id ] = val;

//        console.log( kind[id] );
      }
    }
  }
}

export interface KindConstructor
{
  new ( ...args ): Kind;

  kindInfo?: KindInfo;
}
