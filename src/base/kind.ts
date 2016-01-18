///
/// @class KindHelper
///
/// Builder for 'Kind' metadata
export class KindHelper
{
  private kindInfo: KindInfo;

  public init( kindName: string, description: string ): KindHelper
  {
    this.kindInfo = {
      //"$schema": "http://json-schema.org/draft-04/schema#",
      title: kindName,
      description: description,
      type: "object",
      properties: {}
    };

    return this;
  }

  public field( name: string, description: string, dataType: string, opts? ): KindHelper
  {
    this.kindInfo.properties[ name ] = {
      description: description,
      type: dataType
    };

    return this;
  }

  seal( kind?: Kind ): KindInfo
  {
    let info = this.kindInfo;

    this.kindInfo = new KindInfo();

//    if ( kind )
//      (typeof kind[ "kindInfo = info;

    return info;
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

/*class Integer {};

var Types: { [string]:Object };

var x = new Integer( );
console.log( x );

//export class Integer {};*/

export class Enum {};

export interface FieldInfo {

  description: string;
  dataType: typeof Number | String | Enum | FieldInfo[] | KindInfo;
  kindInfo?: KindInfo;
  enumInfo?: Map<number, string>;
  minLength?: number;
  maxLength?: number;
}

/**
* Metadata about a Kind. Contains name, description and a map of
* property-descriptors that describe the serializable fields of
* an object of that Kind.
*/
export class KindInfo
{
  static $kindHelper: KindHelper = new KindHelper();

  title: string;

  description: string;

  type: string;

  properties: {};
}

/**
* Represents a serializable and inspectable data-type
* implemented as a hash-map containing key-value pairs,
* along with metadata that describes each field using a json-scheme like
*/
export interface Kind
{
  kindInfo: KindInfo;

  properties: {};
}
