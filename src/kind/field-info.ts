import { ByteArray } from './byte-array';
import { Kind } from './kind';

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

export const FieldTypes = {
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
