import PackageInfo from "./package-info";
import ByteArray from "./byte-array";
import Kind from "./kind";
import KindInfo from "./kind-info";
import TaskScheduler from "./task-scheduler";
import Channel from "./channel";
import EndPoint from "./end-point";
import Packet from "./packet";

var $packageInfo: PackageInfo =
{
  name: "simCore.base",

  description: "Simulation-Core Base Classes",

  author: "SE:Core Team",

  members: {
    "ByteArray": ByteArray,
//    "Kind": Kind,
    "KindInfo": KindInfo,
    "TaskScheduler": TaskScheduler,
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
  Channel,
  EndPoint,
  Packet,
};
