import { Graph } from './graph';
import { Node } from './node';

export default class GraphTester {
  graph;

  execTests()
  {
    let graph = {
      id: "gr",
      componentName: "g",

      ports: {
        "pxa": { direction: "inout", "type": "PublicPort" },
        "pxb": {},
      },

      nodes: {
        "n1": {
          componentName: "a",
          ports: {
            "p1a": { direction: "out", },
            "p1b": { direction: "inout", },
            "p1x": { direction: "inout", },
          },
        },
        "n2": {
          componentName: "b",
          ports: {
            "p2a": { direction: "in", },
            "p2b": { direction: "inout", },
          },
        },

      },

      links: {
        "lx": {
          from: { nodeID: "gr", portID: "pxa" },
          to: { nodeID: "n1", portID: "p1x" },
          protocolID: "data"
        },
        "l1": {
          from: { nodeID: "n1", portID: "p1a" },
          to: { nodeID: "n2", portID: "p2a" },
          protocolID: "data"
        },
        "l2": {
          from: { nodeID: "n1", portID: "p1b" },
          to: { nodeID: "n2", portID: "p2b" },
          protocolID: "data"
        },
      },
    };

    this.graph = new Graph( null, graph );
    let gr = this.graph;

    let n1: Node = gr.getNodeByID( "n1" );
    let p1x = n1.getPortByID( "p1x" );
    let p2a = gr.getNodeByID( "n2" ).getPortByID( "p2a" );
  }
}
