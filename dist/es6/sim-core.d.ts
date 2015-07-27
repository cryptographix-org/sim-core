declare module 'sim-core'
{
import * as forge from 'forge';

  export class Key {
      protected id: string;
      protected keyComponents: any[];
      constructor(id: string, attributes: any);
      getComponent(componentID: string): any;
      setComponent(componentID: string, value: any): void;
  }
  
  
  export class PublicKey extends Key {
  }
  
  export class CryptographicServiceProvider {
      constructor();
      makePublicKey(m: string, e: string): forge.rsa.PublicKey;
      decrypt(cg: string, pk: forge.rsa.PublicKey): string;
      static BN: any;
  }
  
  export class SimulationEngine {
  }
  
  export class ByteArray {
      byteArray: Uint8Array;
      length: Number;
      constructor(bytes: any | ByteArray | number | Array<number> | String, opt?: any);
      byteAt(offset: number): Number;
      wordAt(offset: number): number;
      littleEndianWordAt(offset: any): number;
      dwordAt(offset: number): number;
      bytes(offset: any, count: any): ByteArray;
  }
  
  export type Task = () => void;
  export type FlushFunc = () => void;
  export class TaskScheduler {
      static makeRequestFlushFromMutationObserver(flush: any): FlushFunc;
      static makeRequestFlushFromTimer(flush: any): FlushFunc;
      static BrowserMutationObserver: any;
      static hasSetImmediate: boolean;
      static taskQueueCapacity: number;
      taskQueue: Task[];
      requestFlushTaskQueue: FlushFunc;
      constructor();
      queueTask(task: any): void;
      flushTaskQueue(): void;
      onError(error: any, task: any): void;
  }
  
  export class KindHelper {
      private kindInfo;
      init(kindName: string, description: string): KindHelper;
      field(name: string, description: string, dataType: string, opts?: any): KindHelper;
      seal(): KindInfo;
  }
  export class KindInfo {
      static $kindHelper: KindHelper;
      title: string;
      description: string;
      "type": string;
      properties: {};
  }
  export interface Kind {
      kindInfo: KindInfo;
      properties: {};
  }
  
  
  export class Message {
      private header;
      private payload;
      constructor(header: {}, payload: Kind);
      getHeader(): Object;
      getPayload(): Kind;
  }
  
  
  
  export enum Direction {
      IN = 0,
      OUT = 1,
      INOUT = 2,
  }
  export type OnEventDelegate = (fromEndPoint: EndPoint, event: any) => void;
  export type OnMessageDelegate = (fromEndPoint: EndPoint, message: Message) => void;
  export type EndPoints = {
      [id: string]: EndPoint;
  };
  export class EndPoint {
      protected channel: Channel;
      protected eventListeners: OnEventDelegate[];
      protected messageListeners: OnMessageDelegate[];
      direction: Direction;
      constructor(direction?: Direction);
      shutdown(): void;
      connect(channel: Channel): void;
      disconnect(): void;
      isConnected: boolean;
      triggerEvent(event: any): void;
      sendMessage(message: Message): void;
      onEvent(eventListener: OnEventDelegate): void;
      onMessage(messageListener: OnMessageDelegate): void;
      static Direction: Direction;
  }
  
  
  
  
  export class EndPointEntry {
      endPoint: EndPoint;
      direction: Direction;
      eventListener: OnEventDelegate;
      messageListener: OnMessageDelegate;
  }
  export class Channel {
      connected: boolean;
      endPointRegistry: EndPointEntry[];
      taskScheduler: TaskScheduler;
      constructor();
      isConnected: boolean;
      connect(): void;
      disconnect(): void;
      addEndPoint(endPoint: EndPoint, eventListener: OnEventDelegate, messageListener: OnMessageDelegate): void;
      removeEndPoint(endPoint: EndPoint): void;
      getEndPoints(): EndPoint[];
      triggerEvent(origin: EndPoint, event: any): void;
      sendMessage(origin: EndPoint, message: Message): void;
  }
  
  
  export type InjectType = (string[] | (() => string[]));
  export interface Component {
      onCreate?(initialData: Object): any;
      onDestroy?(): any;
      onStart?(endPoints: EndPoints): any;
      onStop?(): any;
  }
  
  
  
  export class xComponent implements Component {
      static $inject: InjectType;
      onCreate(initialData: Object): void;
      onDestroy(): void;
      onStart(endPoints: EndPoints): void;
      onPause(): void;
      onResume(): void;
      onStop(): void;
  }
  export type ComponentType = typeof xComponent;
  export class ComponentRegistry {
      components: Component[];
      constructor();
      setComponent(name: string, comp: Component): void;
      getComponent(name: string): ComponentType;
      protected loadComponent(name: string): Promise<ComponentType>;
      getComponentInstance(name: string, initialData: Object): Promise<Component>;
  }
  
  export interface PackageInfo {
      title: String;
      description: String;
      author: String;
      members: {};
  }
  
  
  
  
  
  export class Port extends EndPoint {
      protected ownerNode: Node;
      protected _id: string;
      protected _protocolID: string;
      view: any;
      constructor(owner: Node, attributes: any);
      toObject(opts?: any): Object;
      id: string;
      node: Node;
      protocol: string;
  }
  export class PublicPort extends Port {
      protected ownerNode: Node;
      proxyEndPoint: EndPoint;
      proxyChannel: Channel;
      constructor(owner: Graph, attributes: any);
      connectPrivate(channel: Channel): void;
      disconnectPrivate(): void;
      toObject(opts?: any): Object;
  }
  
  
  
  
  
  export class Node {
      protected ownerGraph: Graph;
      protected _id: string;
      protected ports: {
          [id: string]: Port;
      };
      protected componentName: string;
      protected setupData: Object;
      view: any;
      protected component: Component;
      constructor(owner: Graph, attributes: any);
      toObject(opts?: any): Object;
      initializeComponent(registry: ComponentRegistry): Promise<void>;
      addPort(id: string, attributes: any): Port;
      id: string;
      getPorts(): Port[];
      getPortByID(id: string): Port;
      identifyPort(id: string, protocol?: string): Port;
  }
  
  
  
  
  
  export type EndPointRef = {
      nodeID: string;
      portID: string;
  };
  export class Link {
      protected ownerGraph: Graph;
      protected _id: string;
      protected channel: Channel;
      protected from: EndPointRef;
      protected to: EndPointRef;
      protected _protocolID: string;
      protected static propertyMap: {
          protocol: string;
          from: string;
          to: string;
      };
      constructor(owner: Graph, link: any);
      toObject(opts?: any): Object;
      id: string;
      connect(channel: Channel): void;
      disconnect(): void;
      fromNode: Node;
      fromPort: Port;
      toNode: Node;
      toPort: Port;
      protocolID: string;
  }
  
  
  
  export class Network {
      private graph;
      private nodes;
      private links;
      private ports;
      private componentRegistry;
      constructor(graph: Graph, componentRegistry: ComponentRegistry);
      initialize(): Promise<void>;
      protected initializeGraph(): Promise<void>;
      wireupGraph(router: any): void;
  }
  
  
  
  
  
  export class Graph extends Node {
      protected nodes: {
          [id: string]: Node;
      };
      protected links: {
          [id: string]: Link;
      };
      constructor(owner: Graph, attributes: any);
      toObject(opts: any): Object;
      initializeComponent(registry: ComponentRegistry): Promise<void>;
      getNodes(): {
          [id: string]: Node;
      };
      getAllNodes(): Node[];
      getLinks(): {
          [id: string]: Link;
      };
      getAllLinks(): Link[];
      getAllPorts(): Port[];
      getNodeByID(id: string): Node;
      addNode(id: string, attributes: {}): Node;
      renameNode(id: string, newID: string): void;
      removeNode(id: string): void;
      getLinkByID(id: string): Link;
      addLink(id: string, attributes: {}): Link;
      renameLink(id: string, newID: string): void;
      removeLink(id: string): void;
      addPublicPort(id: string, attributes: any): PublicPort;
  }
  
  export default class GraphTester {
      graph: any;
      execTests(): void;
  }
  }
