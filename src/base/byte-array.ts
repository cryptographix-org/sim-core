'use strict'

/*var Arr: { new ( tam ); } = (typeof Uint8Array !== 'undefined')
  ? Uint8Array
  : Array*/

class HexCodec
{
  private static hexDecodeMap: number[];

  static decode( a: string ): Uint8Array
  {
    if ( HexCodec.hexDecodeMap == undefined )
    {
      var hex = "0123456789ABCDEF";
      var allow = " \f\n\r\t\u00A0\u2028\u2029";
      var dec = [];
      for (var i = 0; i < 16; ++i)
          dec[hex.charAt(i)] = i;
      hex = hex.toLowerCase();
      for (var i = 10; i < 16; ++i)
          dec[hex.charAt(i)] = i;
      for (var i = 0; i < allow.length; ++i)
          dec[allow.charAt(i)] = -1;
      HexCodec.hexDecodeMap = dec;
    }

    var out = [];
    var bits = 0, char_count = 0;
    for (var i = 0; i < a.length; ++i)
    {
      var c = a.charAt(i);
      if (c == '=')
          break;
      var b = HexCodec.hexDecodeMap[c];
      if (b == -1)
          continue;
      if (b == undefined)
          throw 'Illegal character at offset ' + i;
      bits |= b;
      if (++char_count >= 2) {
          out.push( bits );
          bits = 0;
          char_count = 0;
      } else {
          bits <<= 4;
      }
    }

    if (char_count)
      throw "Hex encoding incomplete: 4 bits missing";

    return Uint8Array.from( out );
  }
}

enum BASE64SPECIALS {
  PLUS = '+'.charCodeAt(0),
  SLASH = '/'.charCodeAt(0),
  NUMBER = '0'.charCodeAt(0),
  LOWER = 'a'.charCodeAt(0),
  UPPER = 'A'.charCodeAt(0),
  PLUS_URL_SAFE = '-'.charCodeAt(0),
  SLASH_URL_SAFE = '_'.charCodeAt(0)
}

class Base64Codec
{
  static decode( b64: string ): Uint8Array
  {
    var i, j, l, tmp, placeHolders, arr;

    if (b64.length % 4 > 0) {
      throw new Error('Invalid base64 string. Length must be a multiple of 4');
    }

    function decode( elt: String ): number
    {
      var code = elt.charCodeAt(0);

      if (code === BASE64SPECIALS.PLUS || code === BASE64SPECIALS.PLUS_URL_SAFE)
        return 62; // '+'

      if (code === BASE64SPECIALS.SLASH || code === BASE64SPECIALS.SLASH_URL_SAFE)
        return 63; // '/'

      if (code >= BASE64SPECIALS.NUMBER)
      {
        if (code < BASE64SPECIALS.NUMBER + 10)
          return code - BASE64SPECIALS.NUMBER + 26 + 26;

        if (code < BASE64SPECIALS.UPPER + 26)
          return code - BASE64SPECIALS.UPPER;

        if (code < BASE64SPECIALS.LOWER + 26)
          return code - BASE64SPECIALS.LOWER + 26;
      }

      throw new Error('Invalid base64 string. Character not valid');
    }

    // the number of equal signs (place holders)
    // if there are two placeholders, than the two characters before it
    // represent one byte
    // if there is only one, then the three characters before it represent 2 bytes
    // this is just a cheap hack to not do indexOf twice
    var len = b64.length;
    placeHolders = b64.charAt(len - 2) === '=' ? 2 : b64.charAt(len - 1) === '=' ? 1 : 0;

    // base64 is 4/3 + up to two characters of the original data
    arr = new Uint8Array( b64.length * 3 / 4 - placeHolders );

    // if there are placeholders, only get up to the last complete 4 chars
    l = placeHolders > 0 ? b64.length - 4 : b64.length;

    var L = 0;

    function push (v) {
      arr[L++] = v;
    }

    for (i = 0, j = 0; i < l; i += 4, j += 3) {
      tmp = (decode(b64.charAt(i)) << 18) | (decode(b64.charAt(i + 1)) << 12) | (decode(b64.charAt(i + 2)) << 6) | decode(b64.charAt(i + 3));
      push((tmp & 0xFF0000) >> 16);
      push((tmp & 0xFF00) >> 8);
      push(tmp & 0xFF);
    }

    if (placeHolders === 2) {
      tmp = (decode(b64.charAt(i)) << 2) | (decode(b64.charAt(i + 1)) >> 4);
      push(tmp & 0xFF);
    } else if (placeHolders === 1) {
      tmp = (decode(b64.charAt(i)) << 10) | (decode(b64.charAt(i + 1)) << 4) | (decode(b64.charAt(i + 2)) >> 2);
      push((tmp >> 8) & 0xFF);
      push(tmp & 0xFF);
    }

    return arr;
  }

  static encode( uint8: Uint8Array ): string
  {
    var i;
    var extraBytes = uint8.length % 3; // if we have 1 byte left, pad 2 bytes
    var output = '';
    var temp, length;

    const lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    function encode( num ) {
      return lookup.charAt(num);
    }

    function tripletToBase64( num ) {
      return encode(num >> 18 & 0x3F) + encode(num >> 12 & 0x3F) + encode(num >> 6 & 0x3F) + encode(num & 0x3F);
    }

    // go through the array every three bytes, we'll deal with trailing stuff later
    for (i = 0, length = uint8.length - extraBytes; i < length; i += 3) {
      temp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2]);
      output += tripletToBase64(temp);
    }

    // pad the end with zeros, but make sure to not forget the extra bytes
    switch (extraBytes) {
      case 1:
        temp = uint8[uint8.length - 1];
        output += encode(temp >> 2);
        output += encode((temp << 4) & 0x3F);
        output += '==';
        break
      case 2:
        temp = (uint8[uint8.length - 2] << 8) + (uint8[uint8.length - 1]);
        output += encode(temp >> 10);
        output += encode((temp >> 4) & 0x3F);
        output += encode((temp << 2) & 0x3F);
        output += '=';
        break
      default:
        break;
    }

    return output;
  }
}

export class ByteArray
{
  public byteArray: Uint8Array;
  public length: Number;

  constructor( bytes: any | ByteArray | number | Array<number> | String | ArrayBuffer, opt?: any )
  {
    if ( bytes instanceof ArrayBuffer )
      this.byteArray = new Uint8Array( <ArrayBuffer>bytes );
    else if ( bytes instanceof ByteArray )
      this.byteArray = bytes.byteArray;
    else if ( bytes instanceof Array )
      this.byteArray = new Uint8Array( bytes );
    else if ( typeof bytes == "string" )
    {
      if ( opt.format && opt.format.toLowerCase() == 'base64' )
      {
          this.byteArray = Base64Codec.decode( <string>bytes );
      }
      else if ( opt.format && opt.format.toLowerCase() == 'hex' )
      {
        this.byteArray = HexCodec.decode( <string>bytes );
      }
      else
      {
        this.byteArray = new Uint8Array( bytes );
      }
    }
    else if ( bytes instanceof Uint8Array )
      this.byteArray = bytes;

    this.length = ( bytes ) ? this.byteArray.length : 0;
  }

  byteAt( offset: number ): Number
  {
    return this.byteArray[ offset ];
  }

  wordAt( offset: number ): number
  {
    return ( this.byteArray[ offset     ] <<  8 )
         + ( this.byteArray[ offset + 1 ]       );
  }

  littleEndianWordAt( offset ): number
  {
    return ( this.byteArray[ offset     ] )
         + ( this.byteArray[ offset + 1 ] <<  8 );
  }

  dwordAt( offset: number ): number
  {
    return ( this.byteArray[ offset     ] << 24 )
         + ( this.byteArray[ offset + 1 ] << 16 )
         + ( this.byteArray[ offset + 2 ] <<  8 )
         + ( this.byteArray[ offset + 3 ]       );
  }

  bytes( offset, count ): ByteArray
  {
    return new ByteArray( this.byteArray.subarray( offset, offset + count ) );
  }

  toString( opt: {} = {} )
  {
    let s = "";
    for( var i = 0; i < this.length; ++i )
      s += ( "0" + this.byteArray[ i ].toString( 16 )).substring( -2 );

    return s;
  }
}
