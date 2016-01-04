System.register(['aurelia-dependency-injection'], function (_export) {
    'use strict';

    var Container, inject, BASE64SPECIALS, Base64Codec, HexCodec, ByteArray, KindHelper, KindInfo, Key, PrivateKey, PublicKey, KeyPair, CryptographicService, Message, KindMessage, window, TaskScheduler, Channel, Direction, EndPoint, ProtocolTypeBits, Protocol, ClientServerProtocol, APDU, APDUMessage, APDUProtocol, ComponentBuilder, PortInfo, ComponentInfo, C, ComponentContext, ModuleRegistryEntry, ModuleLoader, ComponentFactory, Port, PublicPort, Node, Link, Network, Graph, SimulationEngine;

    var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();

    function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

    function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }

    return {
        setters: [function (_aureliaDependencyInjection) {
            Container = _aureliaDependencyInjection.Container;
            inject = _aureliaDependencyInjection.autoinject;
        }],
        execute: function () {
            (function (BASE64SPECIALS) {
                BASE64SPECIALS[BASE64SPECIALS["PLUS"] = '+'.charCodeAt(0)] = "PLUS";
                BASE64SPECIALS[BASE64SPECIALS["SLASH"] = '/'.charCodeAt(0)] = "SLASH";
                BASE64SPECIALS[BASE64SPECIALS["NUMBER"] = '0'.charCodeAt(0)] = "NUMBER";
                BASE64SPECIALS[BASE64SPECIALS["LOWER"] = 'a'.charCodeAt(0)] = "LOWER";
                BASE64SPECIALS[BASE64SPECIALS["UPPER"] = 'A'.charCodeAt(0)] = "UPPER";
                BASE64SPECIALS[BASE64SPECIALS["PLUS_URL_SAFE"] = '-'.charCodeAt(0)] = "PLUS_URL_SAFE";
                BASE64SPECIALS[BASE64SPECIALS["SLASH_URL_SAFE"] = '_'.charCodeAt(0)] = "SLASH_URL_SAFE";
            })(BASE64SPECIALS || (BASE64SPECIALS = {}));

            Base64Codec = (function () {
                function Base64Codec() {
                    _classCallCheck(this, Base64Codec);
                }

                Base64Codec.decode = function decode(b64) {
                    if (b64.length % 4 > 0) {
                        throw new Error('Invalid base64 string. Length must be a multiple of 4');
                    }
                    function decode(elt) {
                        var code = elt.charCodeAt(0);
                        if (code === BASE64SPECIALS.PLUS || code === BASE64SPECIALS.PLUS_URL_SAFE) return 62;
                        if (code === BASE64SPECIALS.SLASH || code === BASE64SPECIALS.SLASH_URL_SAFE) return 63;
                        if (code >= BASE64SPECIALS.NUMBER) {
                            if (code < BASE64SPECIALS.NUMBER + 10) return code - BASE64SPECIALS.NUMBER + 26 + 26;
                            if (code < BASE64SPECIALS.UPPER + 26) return code - BASE64SPECIALS.UPPER;
                            if (code < BASE64SPECIALS.LOWER + 26) return code - BASE64SPECIALS.LOWER + 26;
                        }
                        throw new Error('Invalid base64 string. Character not valid');
                    }
                    var len = b64.length;
                    var placeHolders = b64.charAt(len - 2) === '=' ? 2 : b64.charAt(len - 1) === '=' ? 1 : 0;
                    var arr = new Uint8Array(b64.length * 3 / 4 - placeHolders);
                    var l = placeHolders > 0 ? b64.length - 4 : b64.length;
                    var L = 0;
                    function push(v) {
                        arr[L++] = v;
                    }
                    var i = 0,
                        j = 0;
                    for (; i < l; i += 4, j += 3) {
                        var tmp = decode(b64.charAt(i)) << 18 | decode(b64.charAt(i + 1)) << 12 | decode(b64.charAt(i + 2)) << 6 | decode(b64.charAt(i + 3));
                        push((tmp & 0xFF0000) >> 16);
                        push((tmp & 0xFF00) >> 8);
                        push(tmp & 0xFF);
                    }
                    if (placeHolders === 2) {
                        var tmp = decode(b64.charAt(i)) << 2 | decode(b64.charAt(i + 1)) >> 4;
                        push(tmp & 0xFF);
                    } else if (placeHolders === 1) {
                        var tmp = decode(b64.charAt(i)) << 10 | decode(b64.charAt(i + 1)) << 4 | decode(b64.charAt(i + 2)) >> 2;
                        push(tmp >> 8 & 0xFF);
                        push(tmp & 0xFF);
                    }
                    return arr;
                };

                Base64Codec.encode = function encode(uint8) {
                    var i;
                    var extraBytes = uint8.length % 3;
                    var output = '';
                    var lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
                    function encode(num) {
                        return lookup.charAt(num);
                    }
                    function tripletToBase64(num) {
                        return encode(num >> 18 & 0x3F) + encode(num >> 12 & 0x3F) + encode(num >> 6 & 0x3F) + encode(num & 0x3F);
                    }
                    var length = uint8.length - extraBytes;
                    for (i = 0; i < length; i += 3) {
                        var temp = (uint8[i] << 16) + (uint8[i + 1] << 8) + uint8[i + 2];
                        output += tripletToBase64(temp);
                    }
                    switch (extraBytes) {
                        case 1:
                            var temp = uint8[uint8.length - 1];
                            output += encode(temp >> 2);
                            output += encode(temp << 4 & 0x3F);
                            output += '==';
                            break;
                        case 2:
                            temp = (uint8[uint8.length - 2] << 8) + uint8[uint8.length - 1];
                            output += encode(temp >> 10);
                            output += encode(temp >> 4 & 0x3F);
                            output += encode(temp << 2 & 0x3F);
                            output += '=';
                            break;
                        default:
                            break;
                    }
                    return output;
                };

                return Base64Codec;
            })();

            _export('Base64Codec', Base64Codec);

            HexCodec = (function () {
                function HexCodec() {
                    _classCallCheck(this, HexCodec);
                }

                HexCodec.decode = function decode(a) {
                    if (HexCodec.hexDecodeMap == undefined) {
                        var hex = "0123456789ABCDEF";
                        var allow = ' \f\n\r\t \u2028\u2029';
                        var dec = [];
                        for (var i = 0; i < 16; ++i) dec[hex.charAt(i)] = i;
                        hex = hex.toLowerCase();
                        for (var i = 10; i < 16; ++i) dec[hex.charAt(i)] = i;
                        for (var i = 0; i < allow.length; ++i) dec[allow.charAt(i)] = -1;
                        HexCodec.hexDecodeMap = dec;
                    }
                    var out = [];
                    var bits = 0,
                        char_count = 0;
                    for (var i = 0; i < a.length; ++i) {
                        var c = a.charAt(i);
                        if (c == '=') break;
                        var b = HexCodec.hexDecodeMap[c];
                        if (b == -1) continue;
                        if (b == undefined) throw 'Illegal character at offset ' + i;
                        bits |= b;
                        if (++char_count >= 2) {
                            out.push(bits);
                            bits = 0;
                            char_count = 0;
                        } else {
                            bits <<= 4;
                        }
                    }
                    if (char_count) throw "Hex encoding incomplete: 4 bits missing";
                    return Uint8Array.from(out);
                };

                return HexCodec;
            })();

            _export('HexCodec', HexCodec);

            ByteArray = (function () {
                function ByteArray(bytes, format, opt) {
                    _classCallCheck(this, ByteArray);

                    if (!bytes) {
                        this.byteArray = new Uint8Array(0);
                    } else if (!format || format == ByteArray.BYTES) {
                        if (bytes instanceof ArrayBuffer) this.byteArray = new Uint8Array(bytes);else if (bytes instanceof Uint8Array) this.byteArray = bytes;else if (bytes instanceof ByteArray) this.byteArray = bytes.byteArray;else if (bytes instanceof Array) this.byteArray = new Uint8Array(bytes);
                    } else if (typeof bytes == "string") {
                        if (format == ByteArray.BASE64) {
                            this.byteArray = Base64Codec.decode(bytes);
                        } else if (format == ByteArray.HEX) {
                            this.byteArray = HexCodec.decode(bytes);
                        } else if (format == ByteArray.UTF8) {
                            var l = bytes.length;
                            var ba = new Uint8Array(l);
                            for (var i = 0; i < l; ++i) {
                                ba[i] = bytes.charCodeAt(i);
                            }this.byteArray = ba;
                        }
                    }
                    if (!this.byteArray) {
                        throw new Error("Invalid Params for ByteArray()");
                    }
                }

                ByteArray.prototype.equals = function equals(value) {
                    var ba = this.byteArray;
                    var vba = value.byteArray;
                    var ok = ba.length == vba.length;
                    if (ok) {
                        for (var i = 0; i < ba.length; ++i) {
                            ok = ok && ba[i] == vba[i];
                        }
                    }
                    return ok;
                };

                ByteArray.prototype.byteAt = function byteAt(offset) {
                    return this.byteArray[offset];
                };

                ByteArray.prototype.wordAt = function wordAt(offset) {
                    return (this.byteArray[offset] << 8) + this.byteArray[offset + 1];
                };

                ByteArray.prototype.littleEndianWordAt = function littleEndianWordAt(offset) {
                    return this.byteArray[offset] + (this.byteArray[offset + 1] << 8);
                };

                ByteArray.prototype.dwordAt = function dwordAt(offset) {
                    return (this.byteArray[offset] << 24) + (this.byteArray[offset + 1] << 16) + (this.byteArray[offset + 2] << 8) + this.byteArray[offset + 3];
                };

                ByteArray.prototype.setByteAt = function setByteAt(offset, value) {
                    this.byteArray[offset] = value;
                    return this;
                };

                ByteArray.prototype.setBytesAt = function setBytesAt(offset, value) {
                    this.byteArray.set(value.byteArray, offset);
                    return this;
                };

                ByteArray.prototype.bytesAt = function bytesAt(offset, count) {
                    return new ByteArray(this.byteArray.slice(offset, count));
                };

                ByteArray.prototype.viewAt = function viewAt(offset, count) {
                    return new ByteArray(this.byteArray.slice(offset, count));
                };

                ByteArray.prototype.addByte = function addByte(value) {
                    this.byteArray[this.byteArray.length] = value;
                    return this;
                };

                ByteArray.prototype.setLength = function setLength(len) {
                    this.length = len;
                    return this;
                };

                ByteArray.prototype.concat = function concat(bytes) {
                    var ba = this.byteArray;
                    this.byteArray = new Uint8Array(ba.length + bytes.length);
                    this.byteArray.set(ba);
                    this.byteArray.set(bytes.byteArray, ba.length);
                    return this;
                };

                ByteArray.prototype.clone = function clone() {
                    return new ByteArray(this.byteArray.slice());
                };

                ByteArray.prototype.not = function not() {
                    var ba = this.byteArray;
                    for (var i = 0; i < ba.length; ++i) {
                        ba[i] = ba[i] ^ 0xFF;
                    }return this;
                };

                ByteArray.prototype.and = function and(value) {
                    var ba = this.byteArray;
                    var vba = value.byteArray;
                    for (var i = 0; i < ba.length; ++i) {
                        ba[i] = ba[i] & vba[i];
                    }return this;
                };

                ByteArray.prototype.or = function or(value) {
                    var ba = this.byteArray;
                    var vba = value.byteArray;
                    for (var i = 0; i < ba.length; ++i) {
                        ba[i] = ba[i] | vba[i];
                    }return this;
                };

                ByteArray.prototype.xor = function xor(value) {
                    var ba = this.byteArray;
                    var vba = value.byteArray;
                    for (var i = 0; i < ba.length; ++i) {
                        ba[i] = ba[i] ^ vba[i];
                    }return this;
                };

                ByteArray.prototype.toString = function toString(format, opt) {
                    var s = "";
                    for (var i = 0; i < this.length; ++i) s += ("0" + this.byteArray[i].toString(16)).substring(-2);
                    return s;
                };

                _createClass(ByteArray, [{
                    key: 'length',
                    get: function get() {
                        return this.byteArray.length;
                    },
                    set: function set(len) {
                        if (this.byteArray.length >= len) {
                            this.byteArray = this.byteArray.slice(0, len);
                        } else {
                            var old = this.byteArray;
                            this.byteArray = new Uint8Array(len);
                            this.byteArray.set(old, 0);
                        }
                    }
                }, {
                    key: 'backingArray',
                    get: function get() {
                        return this.byteArray;
                    }
                }]);

                return ByteArray;
            })();

            _export('ByteArray', ByteArray);

            ByteArray.BYTES = 0;
            ByteArray.HEX = 1;
            ByteArray.BASE64 = 2;
            ByteArray.UTF8 = 3;

            KindHelper = (function () {
                function KindHelper() {
                    _classCallCheck(this, KindHelper);
                }

                KindHelper.prototype.init = function init(kindName, description) {
                    this.kindInfo = {
                        title: kindName,
                        description: description,
                        type: "object",
                        properties: {}
                    };
                    return this;
                };

                KindHelper.prototype.field = function field(name, description, dataType, opts) {
                    this.kindInfo.properties[name] = {
                        description: description,
                        type: dataType
                    };
                    return this;
                };

                KindHelper.prototype.seal = function seal(kind) {
                    var info = this.kindInfo;
                    this.kindInfo = new KindInfo();
                    return info;
                };

                return KindHelper;
            })();

            _export('KindHelper', KindHelper);

            KindInfo = function KindInfo() {
                _classCallCheck(this, KindInfo);
            };

            _export('KindInfo', KindInfo);

            KindInfo.$kindHelper = new KindHelper();

            Key = (function () {
                function Key(id, key) {
                    _classCallCheck(this, Key);

                    this.id = id;
                    if (key) this.cryptoKey = key;else {
                        this.cryptoKey = {
                            type: "",
                            algorithm: "",
                            extractable: true,
                            usages: []
                        };
                    }
                }

                _createClass(Key, [{
                    key: 'type',
                    get: function get() {
                        return this.cryptoKey.type;
                    }
                }, {
                    key: 'algorithm',
                    get: function get() {
                        return this.cryptoKey.algorithm;
                    }
                }, {
                    key: 'extractable',
                    get: function get() {
                        return this.cryptoKey.extractable;
                    }
                }, {
                    key: 'usages',
                    get: function get() {
                        return this.cryptoKey.usages;
                    }
                }, {
                    key: 'innerKey',
                    get: function get() {
                        return this.cryptoKey;
                    }
                }]);

                return Key;
            })();

            _export('Key', Key);

            PrivateKey = (function (_Key) {
                _inherits(PrivateKey, _Key);

                function PrivateKey() {
                    _classCallCheck(this, PrivateKey);

                    _Key.apply(this, arguments);
                }

                return PrivateKey;
            })(Key);

            _export('PrivateKey', PrivateKey);

            PublicKey = (function (_Key2) {
                _inherits(PublicKey, _Key2);

                function PublicKey() {
                    _classCallCheck(this, PublicKey);

                    _Key2.apply(this, arguments);
                }

                return PublicKey;
            })(Key);

            _export('PublicKey', PublicKey);

            KeyPair = function KeyPair() {
                _classCallCheck(this, KeyPair);
            };

            _export('KeyPair', KeyPair);

            CryptographicService = (function () {
                function CryptographicService() {
                    _classCallCheck(this, CryptographicService);

                    this.crypto = window.crypto.subtle;
                    if (!this.crypto && msrcrypto) this.crypto = msrcrypto;
                }

                CryptographicService.prototype.decrypt = function decrypt(algorithm, key, data) {
                    var _this = this;

                    return new Promise(function (resolve, reject) {
                        _this.crypto.decrypt(algorithm, key.innerKey, data.backingArray).then(function (res) {
                            resolve(new ByteArray(res));
                        })['catch'](function (err) {
                            reject(err);
                        });
                    });
                };

                CryptographicService.prototype.digest = function digest(algorithm, data) {
                    var _this2 = this;

                    return new Promise(function (resolve, reject) {
                        _this2.crypto.digest(algorithm, data.backingArray).then(function (res) {
                            resolve(new ByteArray(res));
                        })['catch'](function (err) {
                            reject(err);
                        });
                    });
                };

                CryptographicService.prototype.encrypt = function encrypt(algorithm, key, data) {
                    var _this3 = this;

                    return new Promise(function (resolve, reject) {
                        _this3.crypto.encrypt(algorithm, key.innerKey, data.backingArray).then(function (res) {
                            resolve(new ByteArray(res));
                        })['catch'](function (err) {
                            reject(err);
                        });
                    });
                };

                CryptographicService.prototype.exportKey = function exportKey(format, key) {
                    var _this4 = this;

                    return new Promise(function (resolve, reject) {
                        _this4.crypto.exportKey(format, key.innerKey).then(function (res) {
                            resolve(new ByteArray(res));
                        })['catch'](function (err) {
                            reject(err);
                        });
                    });
                };

                CryptographicService.prototype.generateKey = function generateKey(algorithm, extractable, keyUsages) {
                    return new Promise(function (resolve, reject) {});
                };

                CryptographicService.prototype.importKey = function importKey(format, keyData, algorithm, extractable, keyUsages) {
                    var _this5 = this;

                    return new Promise(function (resolve, reject) {
                        _this5.crypto.importKey(format, keyData.backingArray, algorithm, extractable, keyUsages).then(function (res) {
                            resolve(res);
                        })['catch'](function (err) {
                            reject(err);
                        });
                    });
                };

                CryptographicService.prototype.sign = function sign(algorithm, key, data) {
                    var _this6 = this;

                    return new Promise(function (resolve, reject) {
                        _this6.crypto.sign(algorithm, key.innerKey, data.backingArray).then(function (res) {
                            resolve(new ByteArray(res));
                        })['catch'](function (err) {
                            reject(err);
                        });
                    });
                };

                CryptographicService.prototype.verify = function verify(algorithm, key, signature, data) {
                    var _this7 = this;

                    return new Promise(function (resolve, reject) {
                        _this7.crypto.verify(algorithm, key.innerKey, signature.backingArray, data.backingArray).then(function (res) {
                            resolve(new ByteArray(res));
                        })['catch'](function (err) {
                            reject(err);
                        });
                    });
                };

                return CryptographicService;
            })();

            _export('CryptographicService', CryptographicService);

            _export('Container', Container);

            _export('inject', inject);

            Message = (function () {
                function Message(header, payload) {
                    _classCallCheck(this, Message);

                    this._header = header || {};
                    this._payload = payload;
                }

                _createClass(Message, [{
                    key: 'header',
                    get: function get() {
                        return this._header;
                    }
                }, {
                    key: 'payload',
                    get: function get() {
                        return this._payload;
                    }
                }]);

                return Message;
            })();

            _export('Message', Message);

            KindMessage = (function (_Message) {
                _inherits(KindMessage, _Message);

                function KindMessage() {
                    _classCallCheck(this, KindMessage);

                    _Message.apply(this, arguments);
                }

                return KindMessage;
            })(Message);

            _export('KindMessage', KindMessage);

            window = window || {};

            TaskScheduler = (function () {
                function TaskScheduler() {
                    _classCallCheck(this, TaskScheduler);

                    this.taskQueue = [];
                    var self = this;
                    if (typeof TaskScheduler.BrowserMutationObserver === 'function') {
                        this.requestFlushTaskQueue = TaskScheduler.makeRequestFlushFromMutationObserver(function () {
                            return self.flushTaskQueue();
                        });
                    } else {
                        this.requestFlushTaskQueue = TaskScheduler.makeRequestFlushFromTimer(function () {
                            return self.flushTaskQueue();
                        });
                    }
                }

                TaskScheduler.makeRequestFlushFromMutationObserver = function makeRequestFlushFromMutationObserver(flush) {
                    var toggle = 1;
                    var observer = new TaskScheduler.BrowserMutationObserver(flush);
                    var node = document.createTextNode('');
                    observer.observe(node, { characterData: true });
                    return function requestFlush() {
                        toggle = -toggle;
                        node["data"] = toggle;
                    };
                };

                TaskScheduler.makeRequestFlushFromTimer = function makeRequestFlushFromTimer(flush) {
                    return function requestFlush() {
                        var timeoutHandle = setTimeout(handleFlushTimer, 0);
                        var intervalHandle = setInterval(handleFlushTimer, 50);
                        function handleFlushTimer() {
                            clearTimeout(timeoutHandle);
                            clearInterval(intervalHandle);
                            flush();
                        }
                    };
                };

                TaskScheduler.prototype.shutdown = function shutdown() {};

                TaskScheduler.prototype.queueTask = function queueTask(task) {
                    if (this.taskQueue.length < 1) {
                        this.requestFlushTaskQueue();
                    }
                    this.taskQueue.push(task);
                };

                TaskScheduler.prototype.flushTaskQueue = function flushTaskQueue() {
                    var queue = this.taskQueue,
                        capacity = TaskScheduler.taskQueueCapacity,
                        index = 0,
                        task;
                    while (index < queue.length) {
                        task = queue[index];
                        try {
                            task.call();
                        } catch (error) {
                            this.onError(error, task);
                        }
                        index++;
                        if (index > capacity) {
                            for (var scan = 0; scan < index; scan++) {
                                queue[scan] = queue[scan + index];
                            }
                            queue.length -= index;
                            index = 0;
                        }
                    }
                    queue.length = 0;
                };

                TaskScheduler.prototype.onError = function onError(error, task) {
                    if ('onError' in task) {
                        task.onError(error);
                    } else if (TaskScheduler.hasSetImmediate) {
                        setImmediate(function () {
                            throw error;
                        });
                    } else {
                        setTimeout(function () {
                            throw error;
                        }, 0);
                    }
                };

                return TaskScheduler;
            })();

            _export('TaskScheduler', TaskScheduler);

            TaskScheduler.BrowserMutationObserver = window["MutationObserver"] || window["WebKitMutationObserver"];
            TaskScheduler.hasSetImmediate = typeof setImmediate === 'function';
            TaskScheduler.taskQueueCapacity = 1024;

            Channel = (function () {
                function Channel() {
                    _classCallCheck(this, Channel);

                    this._active = false;
                    this._endPoints = [];
                }

                Channel.prototype.shutdown = function shutdown() {
                    this._active = false;
                    this._endPoints = [];
                    if (this._taskScheduler) {
                        this._taskScheduler.shutdown();
                        this._taskScheduler = undefined;
                    }
                };

                Channel.prototype.activate = function activate() {
                    this._taskScheduler = new TaskScheduler();
                    this._active = true;
                };

                Channel.prototype.deactivate = function deactivate() {
                    this._taskScheduler = undefined;
                    this._active = false;
                };

                Channel.prototype.addEndPoint = function addEndPoint(endPoint) {
                    this._endPoints.push(endPoint);
                };

                Channel.prototype.removeEndPoint = function removeEndPoint(endPoint) {
                    var idx = this._endPoints.indexOf(endPoint);
                    if (idx >= 0) {
                        this._endPoints.splice(idx, 1);
                    }
                };

                Channel.prototype.sendMessage = function sendMessage(origin, message) {
                    var _this8 = this;

                    var isResponse = message.header && message.header.isResponse;
                    if (!this._active) return;
                    this._endPoints.forEach(function (endPoint) {
                        if (origin != endPoint) {
                            if (endPoint.direction != Direction.OUT || isResponse) {
                                _this8._taskScheduler.queueTask(function () {
                                    endPoint.handleMessage(message, origin, _this8);
                                });
                            }
                        }
                    });
                };

                _createClass(Channel, [{
                    key: 'active',
                    get: function get() {
                        return this._active;
                    }
                }, {
                    key: 'endPoints',
                    get: function get() {
                        return this._endPoints;
                    }
                }]);

                return Channel;
            })();

            _export('Channel', Channel);

            _export('Direction', Direction);

            (function (Direction) {
                Direction[Direction["IN"] = 1] = "IN";
                Direction[Direction["OUT"] = 2] = "OUT";
                Direction[Direction["INOUT"] = 3] = "INOUT";
            })(Direction || _export('Direction', Direction = {}));
            ;

            EndPoint = (function () {
                function EndPoint(id) {
                    var direction = arguments.length <= 1 || arguments[1] === undefined ? Direction.INOUT : arguments[1];

                    _classCallCheck(this, EndPoint);

                    this._id = id;
                    this._direction = direction;
                    this._channels = [];
                    this._messageListeners = [];
                }

                EndPoint.prototype.shutdown = function shutdown() {
                    this.detachAll();
                    this._messageListeners = [];
                };

                EndPoint.prototype.attach = function attach(channel) {
                    this._channels.push(channel);
                    channel.addEndPoint(this);
                };

                EndPoint.prototype.detach = function detach(channelToDetach) {
                    var idx = this._channels.indexOf(channelToDetach);
                    if (idx >= 0) {
                        channelToDetach.removeEndPoint(this);
                        this._channels.splice(idx, 1);
                    }
                };

                EndPoint.prototype.detachAll = function detachAll() {
                    var _this9 = this;

                    this._channels.forEach(function (channel) {
                        channel.removeEndPoint(_this9);
                    });
                    this._channels = [];
                };

                EndPoint.prototype.handleMessage = function handleMessage(message, fromEndPoint, fromChannel) {
                    var _this10 = this;

                    this._messageListeners.forEach(function (messageListener) {
                        messageListener(message, _this10, fromChannel);
                    });
                };

                EndPoint.prototype.sendMessage = function sendMessage(message) {
                    var _this11 = this;

                    this._channels.forEach(function (channel) {
                        channel.sendMessage(_this11, message);
                    });
                };

                EndPoint.prototype.onMessage = function onMessage(messageListener) {
                    this._messageListeners.push(messageListener);
                };

                _createClass(EndPoint, [{
                    key: 'id',
                    get: function get() {
                        return this._id;
                    }
                }, {
                    key: 'attached',
                    get: function get() {
                        return this._channels.length > 0;
                    }
                }, {
                    key: 'direction',
                    get: function get() {
                        return this._direction;
                    }
                }]);

                return EndPoint;
            })();

            _export('EndPoint', EndPoint);

            _export('ProtocolTypeBits', ProtocolTypeBits);

            (function (ProtocolTypeBits) {
                ProtocolTypeBits[ProtocolTypeBits["PACKET"] = 0] = "PACKET";
                ProtocolTypeBits[ProtocolTypeBits["STREAM"] = 1] = "STREAM";
                ProtocolTypeBits[ProtocolTypeBits["ONEWAY"] = 0] = "ONEWAY";
                ProtocolTypeBits[ProtocolTypeBits["CLIENTSERVER"] = 4] = "CLIENTSERVER";
                ProtocolTypeBits[ProtocolTypeBits["PEER2PEER"] = 6] = "PEER2PEER";
                ProtocolTypeBits[ProtocolTypeBits["UNTYPED"] = 0] = "UNTYPED";
                ProtocolTypeBits[ProtocolTypeBits["TYPED"] = 8] = "TYPED";
            })(ProtocolTypeBits || _export('ProtocolTypeBits', ProtocolTypeBits = {}));

            Protocol = function Protocol() {
                _classCallCheck(this, Protocol);
            };

            _export('Protocol', Protocol);

            Protocol.protocolType = 0;

            ClientServerProtocol = (function (_Protocol) {
                _inherits(ClientServerProtocol, _Protocol);

                function ClientServerProtocol() {
                    _classCallCheck(this, ClientServerProtocol);

                    _Protocol.apply(this, arguments);
                }

                return ClientServerProtocol;
            })(Protocol);

            ClientServerProtocol.protocolType = ProtocolTypeBits.CLIENTSERVER | ProtocolTypeBits.TYPED;

            APDU = function APDU() {
                _classCallCheck(this, APDU);
            };

            APDUMessage = (function (_Message2) {
                _inherits(APDUMessage, _Message2);

                function APDUMessage() {
                    _classCallCheck(this, APDUMessage);

                    _Message2.apply(this, arguments);
                }

                return APDUMessage;
            })(Message);

            APDUProtocol = (function (_ClientServerProtocol) {
                _inherits(APDUProtocol, _ClientServerProtocol);

                function APDUProtocol() {
                    _classCallCheck(this, APDUProtocol);

                    _ClientServerProtocol.apply(this, arguments);
                }

                return APDUProtocol;
            })(ClientServerProtocol);

            ComponentBuilder = (function () {
                function ComponentBuilder() {
                    _classCallCheck(this, ComponentBuilder);
                }

                ComponentBuilder.prototype.init = function init(name, description) {
                    this.componentInfo = {
                        name: name,
                        description: description,
                        ports: {}
                    };
                    return this;
                };

                ComponentBuilder.prototype.port = function port(id, direction, opts) {
                    opts = opts || {};
                    this.componentInfo.ports[id] = {
                        direction: direction,
                        protocol: opts.protocol,
                        maxIndex: opts.maxIndex,
                        required: opts.required
                    };
                    return this;
                };

                ComponentBuilder.prototype.install = function install(ctor) {
                    var info = this.componentInfo;
                    this.componentInfo = new ComponentInfo();
                    ctor.componentInfo = info;
                    return info;
                };

                return ComponentBuilder;
            })();

            _export('ComponentBuilder', ComponentBuilder);

            PortInfo = function PortInfo() {
                _classCallCheck(this, PortInfo);

                this.maxIndex = 0;
                this.required = false;
            };

            _export('PortInfo', PortInfo);

            ComponentInfo = function ComponentInfo() {
                _classCallCheck(this, ComponentInfo);

                this.ports = {};
                this.ports = {};
            };

            _export('ComponentInfo', ComponentInfo);

            ComponentInfo.$builder = new ComponentBuilder();

            C = function C() {
                _classCallCheck(this, C);
            };

            ComponentInfo.$builder.install(C);

            ComponentContext = (function () {
                function ComponentContext(factory, id) {
                    _classCallCheck(this, ComponentContext);

                    this.id = id;
                    this.factory = factory;
                    this.container = factory.container.createChild();
                }

                ComponentContext.prototype.componentLoaded = function componentLoaded(instance) {
                    this.instance = instance;
                    instance;
                };

                ComponentContext.prototype.load = function load() {
                    var _this12 = this;

                    var me = this;
                    this.instance = null;
                    return new Promise(function (resolve, reject) {
                        if (!_this12.id || _this12.id == "") resolve();else {
                            _this12.factory.loadComponent(_this12.id).then(function (instance) {
                                me.instance = instance;
                                resolve();
                            })['catch'](function (err) {
                                reject(err);
                            });
                        }
                    });
                };

                _createClass(ComponentContext, [{
                    key: 'component',
                    get: function get() {
                        return this.instance;
                    }
                }]);

                return ComponentContext;
            })();

            _export('ComponentContext', ComponentContext);

            ;

            ModuleRegistryEntry = function ModuleRegistryEntry(address) {
                _classCallCheck(this, ModuleRegistryEntry);
            };

            ModuleLoader = (function () {
                function ModuleLoader() {
                    _classCallCheck(this, ModuleLoader);

                    this.moduleRegistry = new Map();
                }

                ModuleLoader.prototype.getOrCreateModuleRegistryEntry = function getOrCreateModuleRegistryEntry(address) {
                    return this.moduleRegistry[address] || (this.moduleRegistry[address] = new ModuleRegistryEntry(address));
                };

                ModuleLoader.prototype.loadModule = function loadModule(id) {
                    var _this13 = this;

                    var newId = System.normalizeSync(id);
                    var existing = this.moduleRegistry[newId];
                    if (existing) {
                        return Promise.resolve(existing);
                    }
                    return System['import'](newId).then(function (m) {
                        _this13.moduleRegistry[newId] = m;
                        return m;
                    });
                };

                return ModuleLoader;
            })();

            _export('ModuleLoader', ModuleLoader);

            ComponentFactory = (function () {
                function ComponentFactory(loader, container) {
                    _classCallCheck(this, ComponentFactory);

                    this.loader = loader;
                    this.container = container;
                }

                ComponentFactory.prototype.createContext = function createContext(id) {
                    var context = new ComponentContext(this, id);
                    return context;
                };

                ComponentFactory.prototype.loadComponent = function loadComponent(id) {
                    var createComponent = function createComponent(ctor) {
                        var newInstance = null;
                        var injects = [];
                        newInstance = new ctor();
                        return newInstance;
                    };
                    var ctor = this.get(id);
                    if (ctor) {
                        return new Promise(function (resolve, reject) {
                            resolve(createComponent(ctor));
                        });
                    }
                    return null;
                };

                ComponentFactory.prototype.get = function get(id) {
                    return this.components.get(id);
                };

                ComponentFactory.prototype.set = function set(id, type) {
                    this.components.set(id, type);
                };

                return ComponentFactory;
            })();

            _export('ComponentFactory', ComponentFactory);

            Port = (function () {
                function Port(owner, endPoint) {
                    var attributes = arguments.length <= 2 || arguments[2] === undefined ? {} : arguments[2];

                    _classCallCheck(this, Port);

                    if (!endPoint) {
                        var direction = attributes.direction || Direction.INOUT;
                        if (typeof attributes.direction == "string") direction = Direction[direction.toUpperCase()];
                        endPoint = new EndPoint(attributes.id, direction);
                    }
                    this._owner = owner;
                    this._endPoint = endPoint;
                    this._protocolID = attributes['protocol'] || 'any';
                    this.metadata = attributes.metadata || { x: 100, y: 100 };
                }

                Port.prototype.toObject = function toObject(opts) {
                    var port = {
                        id: this._endPoint.id,
                        direction: this._endPoint.direction,
                        protocol: this._protocolID != 'any' ? this._protocolID : undefined,
                        metadata: this.metadata
                    };
                    return port;
                };

                _createClass(Port, [{
                    key: 'endPoint',
                    get: function get() {
                        return this._endPoint;
                    },
                    set: function set(endPoint) {
                        this._endPoint = endPoint;
                    }
                }, {
                    key: 'owner',
                    get: function get() {
                        return this._owner;
                    }
                }, {
                    key: 'protocolID',
                    get: function get() {
                        return this._protocolID;
                    }
                }, {
                    key: 'id',
                    get: function get() {
                        return this._endPoint.id;
                    }
                }, {
                    key: 'direction',
                    get: function get() {
                        return this._endPoint.direction;
                    }
                }]);

                return Port;
            })();

            _export('Port', Port);

            PublicPort = (function (_Port) {
                _inherits(PublicPort, _Port);

                function PublicPort(owner, endPoint, attributes) {
                    var _this14 = this;

                    _classCallCheck(this, PublicPort);

                    _Port.call(this, owner, endPoint, attributes);
                    var proxyDirection = this._endPoint.direction == Direction.IN ? Direction.OUT : this._endPoint.direction == Direction.OUT ? Direction.IN : Direction.INOUT;
                    this.proxyEndPoint = new EndPoint(this._endPoint.id, proxyDirection);
                    this.proxyEndPoint.onMessage(function (message) {
                        _this14._endPoint.handleMessage(message, _this14.proxyEndPoint, _this14.proxyChannel);
                    });
                    this._endPoint.onMessage(function (message) {
                        _this14.proxyEndPoint.sendMessage(message);
                    });
                    this.proxyChannel = null;
                }

                PublicPort.prototype.connectPrivate = function connectPrivate(channel) {
                    this.proxyChannel = channel;
                    this.proxyEndPoint.attach(channel);
                };

                PublicPort.prototype.disconnectPrivate = function disconnectPrivate() {
                    this.proxyEndPoint.detach(this.proxyChannel);
                };

                PublicPort.prototype.toObject = function toObject(opts) {
                    var port = _Port.prototype.toObject.call(this, opts);
                    return port;
                };

                return PublicPort;
            })(Port);

            _export('PublicPort', PublicPort);

            Node = (function () {
                function Node(owner) {
                    var _this15 = this;

                    var attributes = arguments.length <= 1 || arguments[1] === undefined ? {} : arguments[1];

                    _classCallCheck(this, Node);

                    this._owner = owner;
                    this._id = attributes.id || '';
                    this._componentID = attributes.componentID;
                    this._initialData = attributes.initialData || {};
                    this._ports = {};
                    this.metadata = attributes.metadata || {};
                    Object.keys(attributes.ports || {}).forEach(function (id) {
                        _this15.addPlaceholderPort(id, attributes.ports[id]);
                    });
                }

                Node.prototype.toObject = function toObject(opts) {
                    var _this16 = this;

                    var node = {
                        id: this.id,
                        componentID: this._componentID,
                        initialData: this._initialData,
                        ports: {},
                        metadata: this.metadata
                    };
                    Object.keys(this._ports).forEach(function (id) {
                        node.ports[id] = _this16._ports[id].toObject();
                    });
                    return node;
                };

                Node.prototype.addPlaceholderPort = function addPlaceholderPort(id, attributes) {
                    attributes["id"] = id;
                    var port = new Port(this, null, attributes);
                    this._ports[id] = port;
                    return port;
                };

                Node.prototype.getPorts = function getPorts() {
                    var _this17 = this;

                    var ports = [];
                    Object.keys(this._ports).forEach(function (id) {
                        ports.push(_this17._ports[id]);
                    });
                    return ports;
                };

                Node.prototype.getPortByID = function getPortByID(id) {
                    return this._ports[id];
                };

                Node.prototype.identifyPort = function identifyPort(id, protocolID) {
                    var _this18 = this;

                    var port;
                    if (id) port = this._ports[id];else if (protocolID) {
                        Object.keys(this._ports).forEach(function (id) {
                            var p = _this18._ports[id];
                            if (p.protocolID == protocolID) port = p;
                        }, this);
                    }
                    return port;
                };

                Node.prototype.removePort = function removePort(id) {
                    if (this._ports[id]) {
                        delete this._ports[id];
                        return true;
                    }
                    return false;
                };

                Node.prototype.initComponent = function initComponent(factory) {
                    return Promise.resolve(null);
                };

                _createClass(Node, [{
                    key: 'owner',
                    get: function get() {
                        return this._owner;
                    }
                }, {
                    key: 'id',
                    get: function get() {
                        return this._id;
                    },
                    set: function set(id) {
                        this._id = id;
                    }
                }]);

                return Node;
            })();

            _export('Node', Node);

            Link = (function () {
                function Link(owner) {
                    var attributes = arguments.length <= 1 || arguments[1] === undefined ? {} : arguments[1];

                    _classCallCheck(this, Link);

                    this._owner = owner;
                    this._id = attributes.id || "";
                    this._from = attributes['from'];
                    this._to = attributes['to'];
                    this._protocolID = attributes['protocol'] || 'any';
                    this.metadata = attributes.metadata || { x: 100, y: 100 };
                }

                Link.prototype.toObject = function toObject(opts) {
                    var link = {
                        id: this._id,
                        protocol: this._protocolID != 'any' ? this._protocolID : undefined,
                        metadata: this.metadata,
                        from: this._from,
                        to: this._to
                    };
                    return link;
                };

                Link.prototype.connect = function connect(channel) {
                    var fromPort = this.fromNode.identifyPort(this._from.portID, this._protocolID);
                    var toPort = this.toNode.identifyPort(this._to.portID, this._protocolID);
                    this._channel = channel;
                    fromPort.endPoint.attach(channel);
                    toPort.endPoint.attach(channel);
                };

                Link.prototype.disconnect = function disconnect() {
                    var _this19 = this;

                    this._channel.endPoints.forEach(function (endPoint) {
                        endPoint.detach(_this19._channel);
                    });
                    this._channel = undefined;
                };

                _createClass(Link, [{
                    key: 'id',
                    set: function set(id) {
                        this._id = id;
                    }
                }, {
                    key: 'fromNode',
                    get: function get() {
                        return this._owner.getNodeByID(this._from.nodeID);
                    }
                }, {
                    key: 'fromPort',
                    get: function get() {
                        var node = this.fromNode;
                        return node ? node.identifyPort(this._from.portID, this._protocolID) : undefined;
                    },
                    set: function set(port) {
                        this._from = {
                            nodeID: port.owner.id,
                            portID: port.id
                        };
                        this._protocolID = port.protocolID;
                    }
                }, {
                    key: 'toNode',
                    get: function get() {
                        return this._owner.getNodeByID(this._to.nodeID);
                    }
                }, {
                    key: 'toPort',
                    get: function get() {
                        var node = this.toNode;
                        return node ? node.identifyPort(this._to.portID, this._protocolID) : undefined;
                    },
                    set: function set(port) {
                        this._to = {
                            nodeID: port.owner.id,
                            portID: port.id
                        };
                        this._protocolID = port.protocolID;
                    }
                }, {
                    key: 'protocolID',
                    get: function get() {
                        return this._protocolID;
                    }
                }]);

                return Link;
            })();

            _export('Link', Link);

            Network = (function () {
                function Network(graph, factory) {
                    _classCallCheck(this, Network);

                    this.graph = graph;
                    this.factory = factory;
                }

                Network.prototype.initialize = function initialize() {
                    this.nodes = this.graph.getAllNodes();
                    this.links = this.graph.getAllLinks();
                    this.ports = this.graph.getAllPorts();
                    return this.initializeGraph();
                };

                Network.prototype.initializeGraph = function initializeGraph() {
                    return this.graph.initComponent(this.factory);
                };

                Network.prototype.wireupGraph = function wireupGraph(router) {
                    var me = this;
                    this.nodes.forEach(function (node) {});
                    this.links.forEach(function (link) {
                        var fromNode = link.fromNode;
                        var toNode = link.toNode;
                        var channel = new Channel();
                        link.connect(channel);
                        channel.activate();
                    });
                };

                return Network;
            })();

            _export('Network', Network);

            Graph = (function (_Node) {
                _inherits(Graph, _Node);

                function Graph(owner, attributes) {
                    var _this20 = this;

                    _classCallCheck(this, Graph);

                    _Node.call(this, owner, attributes);
                    this.id = attributes.id || "<graph>";
                    this.nodes = {};
                    this.links = {};
                    this.nodes[this.id] = this;
                    Object.keys(attributes.nodes || {}).forEach(function (id) {
                        _this20.addNode(id, attributes.nodes[id]);
                    });
                    Object.keys(attributes.links || {}).forEach(function (id) {
                        _this20.addLink(id, attributes.links[id]);
                    });
                }

                Graph.prototype.toObject = function toObject(opts) {
                    var _this21 = this;

                    var graph = _Node.prototype.toObject.call(this);
                    var nodes = graph["nodes"] = {};
                    Object.keys(this.nodes).forEach(function (id) {
                        var node = _this21.nodes[id];
                        if (node != _this21) nodes[id] = node.toObject();
                    });
                    var links = graph["links"] = {};
                    Object.keys(this.links).forEach(function (id) {
                        links[id] = _this21.links[id].toObject();
                    });
                    return graph;
                };

                Graph.prototype.initComponent = function initComponent(factory) {
                    var _this22 = this;

                    return new Promise(function (resolve, reject) {
                        var pendingCount = 0;
                        Object.keys(_this22.nodes).forEach(function (id) {
                            var node = _this22.nodes[id];
                            if (node != _this22) {
                                pendingCount++;
                                node.initComponent(factory).then(function () {
                                    --pendingCount;
                                    if (pendingCount == 0) resolve();
                                })['catch'](function (reason) {
                                    reject(reason);
                                });
                            }
                        });
                    });
                };

                Graph.prototype.getNodes = function getNodes() {
                    return this.nodes;
                };

                Graph.prototype.getAllNodes = function getAllNodes() {
                    var _this23 = this;

                    var nodes = [];
                    Object.keys(this.nodes).forEach(function (id) {
                        var node = _this23.nodes[id];
                        if (node != _this23 && node instanceof Graph) nodes = nodes.concat(node.getAllNodes());
                        nodes.push(node);
                    });
                    return nodes;
                };

                Graph.prototype.getLinks = function getLinks() {
                    return this.links;
                };

                Graph.prototype.getAllLinks = function getAllLinks() {
                    var _this24 = this;

                    var links = [];
                    Object.keys(this.nodes).forEach(function (id) {
                        var node = _this24.nodes[id];
                        if (node != _this24 && node instanceof Graph) links = links.concat(node.getAllLinks());
                    });
                    Object.keys(this.links).forEach(function (id) {
                        var link = _this24.links[id];
                        links.push(link);
                    });
                    return links;
                };

                Graph.prototype.getAllPorts = function getAllPorts() {
                    var _this25 = this;

                    var ports = _Node.prototype.getPorts.call(this);
                    Object.keys(this.nodes).forEach(function (id) {
                        var node = _this25.nodes[id];
                        if (node != _this25 && node instanceof Graph) ports = ports.concat(node.getAllPorts());else ports = ports.concat(node.getPorts());
                    });
                    return ports;
                };

                Graph.prototype.getNodeByID = function getNodeByID(id) {
                    return this.nodes[id];
                };

                Graph.prototype.addNode = function addNode(id, attributes) {
                    var node = new Node(this, attributes);
                    node.id = id;
                    this.nodes[id] = node;
                    return node;
                };

                Graph.prototype.renameNode = function renameNode(id, newID) {
                    if (id != newID) {
                        var node = this.nodes[id];
                        this.nodes[newID] = node;
                        node.id = newID;
                        delete this.nodes[id];
                    }
                };

                Graph.prototype.removeNode = function removeNode(id) {
                    if (this.nodes[id]) {
                        delete this.nodes[id];
                        return true;
                    }
                    return false;
                };

                Graph.prototype.getLinkByID = function getLinkByID(id) {
                    return this.links[id];
                };

                Graph.prototype.addLink = function addLink(id, attributes) {
                    var link = new Link(this, attributes);
                    link.id = id;
                    this.links[id] = link;
                    return link;
                };

                Graph.prototype.renameLink = function renameLink(id, newID) {
                    var link = this.links[id];
                    link.id = newID;
                    this.links[newID] = link;
                    delete this.links[id];
                };

                Graph.prototype.removeLink = function removeLink(id) {
                    delete this.links[id];
                };

                Graph.prototype.addPublicPort = function addPublicPort(id, attributes) {
                    attributes["id"] = id;
                    var port = new PublicPort(this, null, attributes);
                    this._ports[id] = port;
                    return port;
                };

                return Graph;
            })(Node);

            _export('Graph', Graph);

            SimulationEngine = (function () {
                function SimulationEngine(loader, container) {
                    _classCallCheck(this, SimulationEngine);

                    this.loader = loader;
                    this.container = container;
                }

                SimulationEngine.prototype.getComponentFactory = function getComponentFactory() {
                    return new ComponentFactory(this.loader, this.container);
                };

                return SimulationEngine;
            })();

            _export('SimulationEngine', SimulationEngine);
        }
    };
});