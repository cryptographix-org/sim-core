export class ByteArray
{
  public byteArray: Uint8Array;
  public length: Number;

  constructor( bytes: any | ByteArray | number | Array<number> | String, opt?: any )
  {
    if ( bytes instanceof ByteArray )
      this.byteArray = bytes.byteArray;
    else if ( bytes instanceof Array )
      this.byteArray = new Uint8Array( bytes );
    else if ( typeof bytes == "string" )
    {
      var str = bytes.replace(/ /g,"");
      var len = str.length/2;

      this.byteArray = new Uint8Array( len );

      for( var ii = 0, jj = 0; ii < len; ++ii, jj+=2 )
        this.byteArray[ ii ] = parseInt( str.substring( jj, jj+2 ), 16 );
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
}
