import { ComponentFactory } from '../runtime/component-factory';
import { RuntimeContext, RunState } from '../runtime/runtime-context';
import { EndPoint } from '../messaging/end-point';
import { Channel } from '../messaging/channel';

import { Graph } from './graph';
import { Node } from './node';
import { Link } from './link';
import { Port, PublicPort } from './port';

export class Network
{
  private _graph: Graph;

  private _factory: ComponentFactory;

  constructor( factory: ComponentFactory, graph?: Graph )
  {
    this._factory = factory;
    this._graph = graph || new Graph( null, {} );
  }

  get graph(): Graph {
    return this._graph;
  }

  /**
  * Load all components
  */
  loadComponents(): Promise<void>
  {
    let me = this;

    return this._graph.loadComponent( this._factory );
  }

  setup() {
    Network.setupOrTeardown( this._graph, RunState.READY );
  }

  teardown() {
    Network.setupOrTeardown( this._graph, RunState.LOADED );
  }

  /**
  * Wireup a graph, creating Channel between linked Nodes
  * Acts recursively, wiring up any sub-graphs
  */

  /**
  * Setup or Teardown a node, setting state to READY or LOADED
  */
  private static setupOrTeardown( node: Node, runState: RunState )
  {
    let ctx = node.context;

    // 1. Preprocess
    if ( node instanceof Graph )
    {
      let nodes: Map<string, Node> = node.nodes;

      if ( runState == RunState.LOADED ) {
        // tearing down .. unlink graph first
        let links: Map<string, Link> = node.links;

        // unwire (deactivate and destroy ) the Channel between linked nodes
        links.forEach( ( link ) =>
        {
          Network.unwireLink( link );
        } );
      }

      // treat graph recursively
      nodes.forEach( function( subNode )
      {
        Network.setupOrTeardown( subNode, runState );
      } );
    }

    // Instantiate or Destroy component
    ctx.setRunState( RunState.READY );

    if ( runState == RunState.READY ) {

      if ( node instanceof Graph )
      {
        // setting up .. linkup graph first
        let links: Map<string, Link> = node.links;
        // treat graph recursively

        // 2. wireup (create and activate) a Channel between linked nodes
        links.forEach( ( link ) =>
        {
          Network.wireLink( link );
        } );
      }
    }
  }

  /**
  * Unwire a link, removing the Channel between the linked Nodes
  */
  private static unwireLink( link: Link )
  {
    // get linked nodes (Link finds Nodes in parent Graph)
    let fromNode = link.fromNode;
    let toNode = link.toNode;

    let chan: Channel = link.disconnect();

    if ( chan )
      chan.deactivate();
  }

  /**
  * Wireup a link, creating Channel between the linked Nodes
  */
  private static wireLink( link: Link )
  {
    // get linked nodes (Link finds Nodes in parent Graph)
    let fromNode = link.fromNode;
    let toNode = link.toNode;

    //debugMessage( "Link("+link.id+"): " + link.from + " -> " + link.to + " proto="+link.protocol );

    let channel = new Channel();

    link.connect( channel );

    channel.activate();
  }


  start( initiallyPaused: boolean ) {
    Network.setRunState( this._graph, initiallyPaused ? RunState.PAUSED : RunState.RUNNING );
  }

  step() {
    // TODO: Single-step
  }

  stop() {
    Network.setRunState( this._graph, RunState.READY );
  }

  pause() {
    Network.setRunState( this._graph, RunState.PAUSED );
  }

  resume() {
    Network.setRunState( this._graph, RunState.RUNNING );
  }

  /**
  * Alter run-state of a Node - READY, RUNNING, PAUSED by triggering
  * Acts recursively, altering state of any sub-graphs
  */
  private static setRunState( node: Node, runState: RunState ) {
    //if ( newState in [ NetworkState.RUNNING, NetworkState.READY ] )
    {
      // Propagate RUN, PAUSE and STOP state changes to sub-nets first
      if ( node instanceof Graph )
      {
        let nodes: Map<string, Node> = node.nodes;

        node.nodes.forEach( function( subNode )
        {
          Network.setRunState( subNode, runState );
        } );
      }
    }

    node.context.setRunState( runState );
  }

}
