import { EventHub, EventSubscription } from '../event-hub/event-hub';
import { Kind } from '../kind/kind';
import { EndPoint, EndPointCollection } from '../messaging/end-point';
import { Graph, Node, Link, Port } from '../graph/graph';
import { ComponentFactory} from './component-factory';
import { Component } from '../component/component';

import { Container, Injectable } from '../dependency-injection/container';

import { RunState, Network } from './runtime';

/**
* Runtime context information for a Node and it's Component instance
*/
export class NodeRuntimeContext<CT extends Component> extends EventHub {
  /**
  * The component id / address
  */
  protected _id: string;

  protected _network: Network;

  /**
  * The runtime component instance that this node represents
  */
  protected _instance: CT;

  /**
  * Initial Data for the component instance
  */
  protected _config: {};

  /**
  * A DI container for the component
  */
  protected _container: Container;

  /**
  * The component factory that created us
  */
  protected _factory: ComponentFactory;

  /**
  * The node
  */
  protected _node: Node;

  /**
  *
  *
  */
  constructor(network: Network, id: string, factory: ComponentFactory, container: Container, config: {}, deps: Injectable[] = []) {

    super();

    this._network = network;

    this._factory = factory;

    this._id = id;

    this._config = config;

    this._container = container;

    // Register any context dependencies
    for (let i in deps) {
      if (!this._container.hasResolver(deps[i]))
        this._container.registerSingleton(deps[i], deps[i]);
    }
  }

  get node(): Node {
    return this._node;
  }
  set node(node: Node) {
    this._node = node;

    // make node 'injectable' in container
    this._container.registerInstance(Node, this);
  }

  get instance(): CT {
    return this._instance;
  }

  get container(): Container {
    return this._container;
  }

  load(): Promise<this> {
    let me = this;

    this._instance = null;

    return new Promise<this>((resolve, reject) => {

      // get an instance from the factory
      me._runState = RunState.LOADING;

      this._factory.loadComponent(this, this._id)
        .then((instance: CT) => {
          // Component (and any dependencies) have been loaded
          me._instance = instance;
          me.setRunState(RunState.LOADED);

          resolve(me);
        })
        .catch((err) => {
          // Unable to load
          me._runState = RunState.UNLOADED;

          reject(err);
        });
    });
  }

  _runState: RunState = RunState.UNLOADED;
  get runState() {
    return this._runState;
  }

  private inState(states: RunState[]): boolean {
    return new Set<RunState>(states).has(this._runState);
  }

  /**
  * Transition component to new state
  * Standard transitions, and respective actions, are:
  *   LOADED -> READY      instantiate and initialize component
  *   READY -> LOADED      teardown and destroy component
  *
  *   READY -> RUNNING     start component execution
  *   RUNNING -> READY     stop component execution
  *
  *   RUNNING -> PAUSED    pause component execution
  *   PAUSED -> RUNNING    resume component execution
  *
  */
  setRunState(runState: RunState) {
    let inst = this._instance;

    switch (runState) // target state ..
    {
      case RunState.LOADED: // just loaded, or teardown
        if (this.inState([RunState.READY, RunState.RUNNING, RunState.PAUSED])) {
          // teardown and destroy component
          if (inst.teardown) {
            inst.teardown();

            // and destroy instance
            this._instance = null;
          }
        }
        break;

      case RunState.READY:  // initialize or stop node
        if (this.inState([RunState.LOADED])) {
          // initialize component

          let endPoints: EndPoint[] = [];

          if (inst.initialize)
            endPoints = this.instance.initialize(<Kind>this._config);

          if (this._node)
            this._node.updatePorts(endPoints);
        }
        else if (this.inState([RunState.RUNNING, RunState.PAUSED])) {
          // stop component
          if (inst.stop)
            this.instance.stop();
        }
        else
          throw new Error('Component cannot be initialized, not loaded');
        break;

      case RunState.RUNNING:  // start/resume node
        if (this.inState([RunState.READY, RunState.RUNNING])) {
          // start component execution
          if (inst.start)
            this.instance.start();
        }
        else if (this.inState([RunState.PAUSED])) {
          // resume component execution after pause
          if (inst.resume)
            this.instance.resume();
        }
        else
          throw new Error('Component cannot be started, not ready');
        break;

      case RunState.PAUSED:  // pause node
        if (this.inState([RunState.RUNNING])) {
          if (inst.pause)
            this.instance.pause();
        }
        else if (this.inState([RunState.PAUSED])) {
          // already paused
        }
        else
          throw new Error('Component cannot be paused');
        break;
    }

    this._runState = runState;

    this.publish(NodeRuntimeContext.EVENT_STATE_CHANGE, { state: runState });
  }

  static EVENT_STATE_CHANGE = 'node:state-change';

  release() {
    // release instance, to avoid memory leaks
    this._instance = null;

    this._factory = null
  }
}

export class GraphRuntimeContext<CT extends Component> extends NodeRuntimeContext<CT> {

  node: Graph;

  /**
  * Alter run-state of a Node - LOADED, READY, RUNNING or PAUSED.
  * Triggers Setup or Teardown if transitioning between READY and LOADED
  * Wireup a graph, creating Channel between linked Nodes
  * Acts recursively, wiring up any sub-graphs
  */
  setRunState(runState: RunState) {
    let currentState = this._runState;
    let network = this._network;

    // 1. Preprocess
    //    a. Handle teardown
    //    b. Propagate state change to subnets
    let nodes: Map<string, Node> = this.node.nodes;

    if ((runState == RunState.LOADED) && (currentState >= RunState.READY)) {
      // tearing down .. unlink graph first
      let links = this.node.links;

      // unwire (deactivate and destroy ) Channels between linked nodes
      links.forEach((link) => {
        Network.unwireLink(link);
      });
    }

    // Propagate state change to sub-nets first
    nodes.forEach(function(subNode) {
      network.getNodeContext(subNode).setRunState(runState);
    });

    // 2. Change state ...
    super.setRunState(runState);

    // 3. Postprocess
    //    a. Handle setup
    if ((runState == RunState.READY) && (currentState >= RunState.LOADED)) {

      // setting up .. linkup graph first
      let links = this.node.links;
      // treat graph recursively

      // 2. wireup (create and activate) a Channel between linked nodes
      links.forEach((link) => {
        Network.wireLink(link);
      });
    }
  }


}
