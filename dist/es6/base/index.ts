import PackageInfo from "./package-info";
import ByteArray from "./byte-array";
import Kind from "./kind";
import KindInfo from "./kind-info";
import TaskScheduler from "./task-scheduler";
import Channel from "./channel";
import EndPoint, { EndPoints } from "./end-point";
import Message from "./message";
import ComponentRegistry from "./component-registry";
//import Component from "./component";
import ComponentInterface from "./component-interface";

var $packageInfo: PackageInfo =
{
  title: "simCore.base",

  description: "Simulation-Core Base Classes",

  author: "SE:Core Team",

  members: {
    "ByteArray": ByteArray,
//    "PackageInfo": PackageInfo,
//    "Kind": Kind,
    "KindInfo": KindInfo,
    "TaskScheduler": TaskScheduler,
    "ComponentRegistry": ComponentRegistry,
    "Channel": Channel,
    "EndPoint": EndPoint,
    "Message": Message,
  }
}

export {
  $packageInfo,
  PackageInfo,
  ByteArray,
  Kind,
  KindInfo,
  TaskScheduler,
  ComponentRegistry,
  ComponentInterface,
  Channel,
  EndPoint,
  EndPoints,
  Message,
};
