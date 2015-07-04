export declare class ByteArray {
    byteArray: Uint8Array;
    length: Number;
    constructor(bytes: any | ByteArray | number | Array<number> | String, opt?: any);
    byteAt(offset: number): Number;
    wordAt(offset: number): number;
    littleEndianWordAt(offset: any): number;
    dwordAt(offset: number): number;
    bytes(offset: any, count: any): ByteArray;
}

export declare type Task = () => void;
export declare type FlushFunc = () => void;
export declare class TaskScheduler {
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

export declare class KindHelper {
    private kindInfo;
    init(kindName: string, description: string): KindHelper;
    field(name: string, description: string, dataType: string, opts?: any): KindHelper;
    seal(): KindInfo;
}
export declare class KindInfo {
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

export declare class Message {
    private header;
    private payload;
    constructor(header: {}, payload: Kind);
    getHeader(): Object;
    getPayload(): Kind;
}

export declare enum Direction {
    IN = 0,
    OUT = 1,
    INOUT = 2,
}
export declare type OnEventDelegate = (fromEndPoint: EndPoint, event: any) => void;
export declare type OnMessageDelegate = (fromEndPoint: EndPoint, message: Message) => void;
export declare type EndPoints = {
    [id: string]: EndPoint;
};
export declare class EndPoint {
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

export declare class EndPointEntry {
    endPoint: EndPoint;
    direction: Direction;
    eventListener: OnEventDelegate;
    messageListener: OnMessageDelegate;
}
export declare class Channel {
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

export declare type InjectType = (string[] | (() => string[]));
export interface ComponentInterface {
    onCreate?(initialData: Object): any;
    onDestroy?(): any;
    onStart?(endPoints: EndPoints): any;
    onStop?(): any;
}

export declare class Component implements ComponentInterface {
    static $inject: InjectType;
    onCreate(initialData: Object): void;
    onDestroy(): void;
    onStart(endPoints: EndPoints): void;
    onPause(): void;
    onResume(): void;
    onStop(): void;
}
export declare type ComponentType = typeof Component;
export declare class ComponentRegistry {
    components: ComponentInterface[];
    constructor();
    setComponent(name: string, comp: ComponentInterface): void;
    getComponent(name: string): ComponentType;
    protected loadComponent(name: string): Promise<ComponentType>;
    getComponentInstance(name: string, initialData: Object): Promise<Component>;
}

interface PackageInfo {
    title: String;
    description: String;
    author: String;
    members: {};
}
export default PackageInfo;

export declare class Key {
    protected id: string;
    protected keyComponents: any[];
    constructor(id: string, attributes: any);
    getComponent(componentID: string): any;
    setComponent(componentID: string, value: any): void;
}

export declare class PublicKey extends Key {
}

/// <reference path="../../types/forge/forge.d.ts" />
/// <reference path="../../types/jsbn/jsbn.d.ts" />
export declare class CryptographicServiceProvider {
    constructor();
    makePublicKey(m: string, e: string): forge.rsa.PublicKey;
    decrypt(cg: string, pk: forge.rsa.PublicKey): string;
    static BN: typeof jsbn.BigInteger;
}

export declare class SimulationEngine {
}

export declare class Port extends EndPoint {
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
export declare class PublicPort extends Port {
    protected ownerNode: Node;
    proxyEndPoint: EndPoint;
    proxyChannel: Channel;
    constructor(owner: Graph, attributes: any);
    connectPrivate(channel: Channel): void;
    disconnectPrivate(): void;
    toObject(opts?: any): Object;
}

export declare class Node {
    protected ownerGraph: Graph;
    protected _id: string;
    protected ports: {
        [id: string]: Port;
    };
    protected componentName: string;
    protected setupData: Object;
    view: any;
    protected component: ComponentInterface;
    constructor(owner: Graph, attributes: any);
    toObject(opts?: any): Object;
    initializeComponent(registry: ComponentRegistry): Promise<void>;
    addPort(id: string, attributes: any): Port;
    id: string;
    getPorts(): Port[];
    getPortByID(id: string): Port;
    identifyPort(id: string, protocol?: string): Port;
}

export declare type EndPointRef = {
    nodeID: string;
    portID: string;
};
export declare class Link {
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

export declare class Network {
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

export declare class Graph extends Node {
    protected nodes: {
        [id: string]: Node;
    };
    protected links: {
        [id: string]: Link;
    };
    constructor(owner: Graph, attributes: any);
    toObject(opts: any): Object;
    initializeComponent(registry: ComponentRegistry): Promise<void>;
    getAllNodes(): Node[];
    getAllLinks(): Link[];
    getAllPorts(): Port[];
    getNodeByID(id: string): Node;
    addNode(id: string, attributes: {}): Node;
    renameNode(id: string, newID: string): void;
    removeNode(id: string): void;
    addLink(id: string, attributes: {}): Link;
    renameLink(id: string, newID: string): void;
    removeLink(id: string): void;
    addPublicPort(id: string, attributes: any): PublicPort;
}

export default class GraphTester {
    graph: any;
    execTests(): void;
}
