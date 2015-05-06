import PackageInfo from "../base/package-info";

import Network from "./network";
import Node from "./node";
import Graph from "./graph";
import Link from "./link";
import Port from "./port";
import PublicPort from "./public-port";

var $packageInfo: PackageInfo =
{
  title: "simCore.graph",

  description: "Simulation-Core Graph Classes",

  author: "SE:Core Team",

  members: {
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
  Network,
  Graph,
  Node,
  Link,
  Port,
  PublicPort
};
