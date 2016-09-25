import { ByteArray } from './byte-array';
import { FieldType, FieldTypes, FieldOptions, FieldInfo } from './field-info';

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
    return this.field( name, description, FieldTypes.Integer, opts );
  }

  public uint32Field( name: string, description: string, opts: FieldOptions = {} ): KindBuilder {
    opts.minimum = opts.minimum || 0;
    opts.maximum = opts.maximum || 0xFFFFFFFF;

    return this.field( name, description, FieldTypes.Integer, opts );
  }

  public byteField( name: string, description: string, opts: FieldOptions = {} ): KindBuilder {
    opts.minimum = opts.minimum || 0;
    opts.maximum = opts.maximum || 255;

    return this.field( name, description, FieldTypes.Integer, opts );
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
      let idxx = parseInt( idx );
      if ( idxx != NaN )
        opts.enumMap.set( idxx, enumm[ idx ] );
    }

    return this.field( name, description, FieldTypes.Enum, opts );
  }
}

/**
* Represents a serializable and inspectable data-type
* implemented as a standard javascript object enhanced with metadata
* that describes each field.
*/
export interface Kind
{
  /**
   * Serialization, returns a JSON object
   */
  toJSON?(): {};

  /**
   * Encoder
   */
  encodeBytes?( options?: {} ): ByteArray;

  /**
  * Decoder, chainable
  */
  decodeBytes?( byteArray: ByteArray, options?: {} ): this;
}

export class Kind implements Kind {
  // Quick and Nasty test for "Kind"
  static isKind( kind: Kind ): boolean {
    // !! transforms objects into boolean
    return !!( kind && kind.constructor && (<KindConstructor>(kind.constructor)).kindInfo);
  }

  static getKindConstructor( kind: Kind ): KindConstructor {
    return kind && kind.constructor && <KindConstructor>(kind.constructor);
  }

  static getKindInfo( kind: Kind ): KindInfo {
    return (<KindConstructor>(kind.constructor)).kindInfo;
  }

  static initFields( kind: Kind, attributes: {} = {}  ) {
    let kindInfo = Kind.getKindInfo( kind );

    for( let id in kindInfo.fields ) {
      let field = kindInfo.fields[ id ];
      let fieldType = field.fieldType;

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
        else if ( fieldType == FieldTypes.Integer )
          val = field.minimum || 0;
        else if ( fieldType == Boolean )
          val = false;
        else if ( fieldType == FieldTypes.ByteArray )
          val = new ByteArray();
        else if ( fieldType == FieldTypes.Enum )
          val = field.enumMap.keys[0];
        else if ( fieldType == Kind ) {
          let ctor = (<Kind>fieldType).constructor;
          val = Object.create( ctor );
        }

        kind[ id ] = val;
      }
    }
  }
}

export interface KindConstructor
{
  new ( attributes?: {}, ...args ): Kind;

  kindInfo?: KindInfo;
}
