import PackageInfo from "../base/package-info";

import ComponentRegistry from "./component-registry";
import Component from "./component";
import Network from "./network";
import Node from "./node";
import Graph from "./graph";
import Link from "./link";
import Port from "./port";
import PublicPort from "./public-port";

var $packageInfo: PackageInfo =
{
  name: "simCore.graph",

  description: "Simulation-Core Graph Classes",

  author: "SE:Core Team",

  members: {
    "ComponentRegistry": ComponentRegistry,
    "Component": Component,
    "Network": Network,
    "Graph": Graph,
    "Node": Node,
    "Link": Link,
    "Port": Port,
    "PublicPort": PublicPort,
  }
}

export {
  $packageInfo,
  ComponentRegistry,
  Component,
  Network,
  Graph,
  Node,
  Link,
  Port,
  PublicPort
};
