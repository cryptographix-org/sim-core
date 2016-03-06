import { Component, ComponentBuilder, Kind, KindBuilder } from 'cryptographix-sim-core';
import { Direction, Message, EndPoint } from 'cryptographix-sim-core';

/**
* Example usage ....
*/
class DummyComponent implements Component {

}

class DummyConfig implements Kind {

}

ComponentBuilder
  .init( DummyComponent, 'Dummy', 'A Dummy Component for Dummies' )
  .config( DummyConfig )
  .port( 'p1', 'port for input', Direction.IN )
//  .store( 'p1', 'port for input', Direction.IN )
  ;
