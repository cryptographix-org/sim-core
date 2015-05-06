import PackageInfo from "./package-info";
import ByteArray from "./byte-array";
import Kind from "./kind";
import KindInfo from "./kind-info";
import TaskScheduler from "./task-scheduler";
import Channel from "./channel";
import EndPoint from "./end-point";
import Packet from "./packet";
import ComponentRegistry from "./component-registry";
import Component from "./component";

var $packageInfo: PackageInfo =
{
  title: "simCore.base",

  description: "Simulation-Core Base Classes",

  author: "SE:Core Team",

  members: {
    "ByteArray": ByteArray,
//    "Kind": Kind,
    "KindInfo": KindInfo,
    "TaskScheduler": TaskScheduler,
    "ComponentRegistry": ComponentRegistry,
    "Component": Component,
    "Channel": Channel,
    "EndPoint": EndPoint,
    "Packet": Packet,
  }
}

export {
  $packageInfo,
  ByteArray,
  Kind,
  KindInfo,
  TaskScheduler,
  ComponentRegistry,
  Component,
  Channel,
  EndPoint,
  Packet,
};
