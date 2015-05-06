import PackageInfo from "../base/package-info";

import CryptographicServiceProvider from "./cryptographic-service-provider";
import Key from "./key";

var $packageInfo: PackageInfo =
{
  title: "simCore.crypto",

  description: "Simulation-Core Cryptographic Classes",

  author: "SE:Core Team",

  members: {
    "CryptographicServiceProvider": CryptographicServiceProvider,
    "Key": Key,
  }
}

export {
  $packageInfo,
  CryptographicServiceProvider,
  Key
};
