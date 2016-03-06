import { ByteArray } from '../kind/byte-array';

export enum CryptographicOperation {
  ENCRYPT,
  DECRYPT,
  DIGEST,
  SIGN,
  VERIFY,
  DERIVE_BITS,

  DERIVE_KEY,
  IMPORT_KEY,
  EXPORT_KEY,
  GENERATE_KEY,
  WRAP_KEY,
  UNWRAP_KEY,
}

export interface CryptographicService {
  encrypt?( algorithm: Algorithm, key: CryptoKey, data: ByteArray ): Promise<ByteArray>;
  decrypt?( algorithm: Algorithm, key: CryptoKey, data: ByteArray ): Promise<ByteArray>;

  digest?( algorithm: Algorithm, data: ByteArray ): Promise<ByteArray>;

  sign?( algorithm: Algorithm, key: CryptoKey, data: ByteArray ): Promise<ByteArray>;
  verify?( algorithm: Algorithm, key: CryptoKey, signature: ByteArray, data: ByteArray ): Promise<ByteArray>;

  deriveBits?( algorithm: Algorithm, baseKey: CryptoKey, length: number ): Promise<ByteArray>;
}

export interface CryptographicServiceConstructor {
  new(): CryptographicService;

  supportedOperations?: CryptographicOperation[];
}

export interface CryptographicKeyService {
  deriveKey?( algorithm: Algorithm, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[] ): Promise<CryptoKey>;

  wrapKey?( format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: Algorithm ): Promise<ByteArray>;
  unwrapKey?( format: string, wrappedKey: ByteArray, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: string[]): Promise<CryptoKey>;

  importKey?( format: string, keyData: ByteArray, algorithm: Algorithm, extractable: boolean, keyUsages: string[] ): Promise<CryptoKey>;
  generateKey?( algorithm: Algorithm, extractable: boolean, keyUsages: string[] ): Promise<CryptoKey | CryptoKeyPair>;
  exportKey?( format: string, key: CryptoKey ): Promise<ByteArray>;
}

export interface CryptographicKeyServiceConstructor {
  new(): CryptographicKeyService;

  supportedOperations?: CryptographicOperation[];
}

export class CryptographicServiceRegistry {
  private _serviceMap: Map<string, CryptographicKeyServiceConstructor>;
  private _keyServiceMap: Map<string, CryptographicKeyServiceConstructor>;

  constructor() {
    this._serviceMap = new Map<string, CryptographicServiceConstructor>();
    this._keyServiceMap = new Map<string, CryptographicKeyServiceConstructor>();
  }

  getService( algorithm: string | Algorithm ): { name: string, instance: CryptographicService } {
    let algo = ( algorithm instanceof Object ) ? (<Algorithm>algorithm).name : <string>algorithm;
    let service = this._serviceMap.get( algo );

    return { name: algo, instance: service ? new service() : null };
  }

  getKeyService( algorithm: string | Algorithm ): { name: string, instance: CryptographicKeyService } {
    let algo = ( algorithm instanceof Object ) ? (<Algorithm>algorithm).name : <string>algorithm;
    let service = this._keyServiceMap.get( algo );

    return { name: algo, instance: service ? new service() : null };
  }

  setService( algorithm: string, ctor: CryptographicServiceConstructor, opers: CryptographicOperation[] ) {
    ctor.supportedOperations = opers;

    this._serviceMap.set( algorithm, ctor );
  }
  setKeyService( algorithm: string, ctor: CryptographicServiceConstructor, opers: CryptographicOperation[] ) {
    ctor.supportedOperations = opers;

    this._keyServiceMap.set( algorithm, ctor );
  }
}

export class CryptographicServiceProvider implements CryptographicService, CryptographicKeyService {
  // singleton registry
  private static _registry: CryptographicServiceRegistry = new CryptographicServiceRegistry();

  public static registerService( name: string, ctor: CryptographicServiceConstructor, opers: CryptographicOperation[] ) {
    CryptographicServiceProvider._registry.setService( name, ctor, opers );
  }
  public static registerKeyService( name: string, ctor: CryptographicKeyServiceConstructor, opers: CryptographicOperation[] ) {
    CryptographicServiceProvider._registry.setKeyService( name, ctor, opers );
  }

  get registry(): CryptographicServiceRegistry {
    return CryptographicServiceProvider._registry;
  }

  encrypt(algorithm: string | Algorithm, key: CryptoKey, data: ByteArray): Promise<ByteArray> {
    let { name, instance } = this.registry.getService( algorithm );

    return ( instance && instance.encrypt )
      ? instance.encrypt( name, key, data )
      : Promise.reject<ByteArray>( "" );
  }

  decrypt(algorithm: string | Algorithm, key: CryptoKey, data: ByteArray): Promise<ByteArray> {
    let { name, instance } = this.registry.getService( algorithm );

    return ( instance && instance.decrypt )
      ? instance.decrypt( name, key, data )
      : Promise.reject<ByteArray>( "" );
  }

  digest(algorithm: string | Algorithm, data: ByteArray): Promise<ByteArray> {
    let { name, instance } = this.registry.getService( algorithm );

    return ( instance && instance.digest )
      ? instance.digest( name, data )
      : Promise.reject<ByteArray>( "" );
  }

  sign( algorithm: string | Algorithm, key: CryptoKey, data: ByteArray ): Promise<ByteArray> {
    let { name, instance } = this.registry.getService( algorithm );

    return ( instance && instance.sign )
      ? instance.sign( name, key, data )
      : Promise.reject<ByteArray>( "" );
  }

  verify(algorithm: string | Algorithm, key: CryptoKey, signature: ByteArray, data: ByteArray): Promise<ByteArray> {
    let { name, instance } = this.registry.getService( algorithm );

    return ( instance && instance.verify )
      ? instance.verify( name, key, signature, data )
      : Promise.reject<ByteArray>( "" );
  }

  exportKey( format: string, key: CryptoKey ): Promise<ByteArray> {
    let { name, instance } = this.registry.getKeyService( key.algorithm );

    return ( instance && instance.exportKey )
      ? instance.exportKey( format, key )
      : Promise.reject<ByteArray>( "" );
  }

  generateKey( algorithm: string | Algorithm, extractable: boolean, keyUsages: string[] ): Promise<CryptoKey | CryptoKeyPair> {
    let { name, instance } = this.registry.getKeyService( algorithm );

    return ( instance && instance.generateKey )
      ? instance.generateKey( name, extractable, keyUsages )
      : Promise.reject<CryptoKey | CryptoKeyPair>( "" );
  }

  importKey( format: string, keyData: ByteArray , algorithm: string | Algorithm, extractable: boolean, keyUsages: string[] ): Promise<CryptoKey> {
    let { name, instance } = this.registry.getKeyService( algorithm );

    return ( instance && instance.importKey )
      ? instance.importKey( format, keyData, name, extractable, keyUsages )
      : Promise.reject<CryptoKey>( "" );
  }

  deriveKey( algorithm: Algorithm, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[] ): Promise<CryptoKey> {
    let { name, instance } = this.registry.getKeyService( algorithm );

    return ( instance && instance.deriveKey )
      ? instance.deriveKey( name, baseKey, derivedKeyType, extractable, keyUsages )
      : Promise.reject<CryptoKey>( "" );
  }

  deriveBits( algorithm: Algorithm, baseKey: CryptoKey, length: number ): Promise<ByteArray> {
    let { name, instance } = this.registry.getService( algorithm );

    return ( instance && instance.deriveBits )
      ? instance.deriveBits( name, baseKey, length )
      : Promise.reject<ByteArray>( "" );
  }

  wrapKey( format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: Algorithm ): Promise<ByteArray> {
    let { name, instance } = this.registry.getKeyService( key.algorithm );

    return ( instance && instance.wrapKey )
      ? instance.wrapKey( format, key, wrappingKey, wrapAlgorithm )
      : Promise.reject<ByteArray>( "" );
  }

  unwrapKey( format: string, wrappedKey: ByteArray, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: string[]): Promise<CryptoKey> {
    let { name, instance } = this.registry.getKeyService( unwrapAlgorithm );

    return ( instance && instance.unwrapKey )
      ? instance.unwrapKey( format, wrappedKey, unwrappingKey, name, unwrappedKeyAlgorithm, extractable, keyUsages )
      : Promise.reject<CryptoKey>( "" );
  }
}
