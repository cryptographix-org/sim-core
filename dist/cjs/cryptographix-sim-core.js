'use strict';

exports.__esModule = true;

var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();

function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }

var _aureliaDependencyInjection = require('aurelia-dependency-injection');

var _aureliaEventAggregator = require('aurelia-event-aggregator');

var HexCodec = (function () {
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

exports.HexCodec = HexCodec;

var BASE64SPECIALS;
(function (BASE64SPECIALS) {
    BASE64SPECIALS[BASE64SPECIALS["PLUS"] = '+'.charCodeAt(0)] = "PLUS";
    BASE64SPECIALS[BASE64SPECIALS["SLASH"] = '/'.charCodeAt(0)] = "SLASH";
    BASE64SPECIALS[BASE64SPECIALS["NUMBER"] = '0'.charCodeAt(0)] = "NUMBER";
    BASE64SPECIALS[BASE64SPECIALS["LOWER"] = 'a'.charCodeAt(0)] = "LOWER";
    BASE64SPECIALS[BASE64SPECIALS["UPPER"] = 'A'.charCodeAt(0)] = "UPPER";
    BASE64SPECIALS[BASE64SPECIALS["PLUS_URL_SAFE"] = '-'.charCodeAt(0)] = "PLUS_URL_SAFE";
    BASE64SPECIALS[BASE64SPECIALS["SLASH_URL_SAFE"] = '_'.charCodeAt(0)] = "SLASH_URL_SAFE";
})(BASE64SPECIALS || (BASE64SPECIALS = {}));

var Base64Codec = (function () {
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

exports.Base64Codec = Base64Codec;
var ByteEncoding;
exports.ByteEncoding = ByteEncoding;
(function (ByteEncoding) {
    ByteEncoding[ByteEncoding["RAW"] = 0] = "RAW";
    ByteEncoding[ByteEncoding["HEX"] = 1] = "HEX";
    ByteEncoding[ByteEncoding["BASE64"] = 2] = "BASE64";
    ByteEncoding[ByteEncoding["UTF8"] = 3] = "UTF8";
})(ByteEncoding || (exports.ByteEncoding = ByteEncoding = {}));

var ByteArray = (function () {
    function ByteArray(bytes, encoding, opt) {
        _classCallCheck(this, ByteArray);

        if (!bytes) {
            this.byteArray = new Uint8Array(0);
        } else if (!encoding || encoding == ByteEncoding.RAW) {
            if (bytes instanceof ArrayBuffer) this.byteArray = new Uint8Array(bytes);else if (bytes instanceof Uint8Array) this.byteArray = bytes;else if (bytes instanceof ByteArray) this.byteArray = bytes.byteArray;else if (bytes instanceof Array) this.byteArray = new Uint8Array(bytes);
        } else if (typeof bytes == "string") {
            if (encoding == ByteEncoding.BASE64) {
                this.byteArray = Base64Codec.decode(bytes);
            } else if (encoding == ByteEncoding.HEX) {
                this.byteArray = HexCodec.decode(bytes);
            } else if (encoding == ByteEncoding.UTF8) {
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

    ByteArray.encodingToString = function encodingToString(encoding) {
        switch (encoding) {
            case ByteEncoding.BASE64:
                return 'BASE64';
            case ByteEncoding.UTF8:
                return 'UTF8';
            case ByteEncoding.HEX:
                return 'HEX';
            default:
                return 'RAW';
        }
    };

    ByteArray.stringToEncoding = function stringToEncoding(encoding) {
        if (encoding.toUpperCase() == 'BASE64') return ByteEncoding.BASE64;else if (encoding.toUpperCase() == 'UTF8') return ByteEncoding.UTF8;else if (encoding.toUpperCase() == 'HEX') return ByteEncoding.HEX;else return ByteEncoding.RAW;
    };

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

    ByteArray.prototype.clone = function clone() {
        return new ByteArray(this.byteArray.slice());
    };

    ByteArray.prototype.bytesAt = function bytesAt(offset, count) {
        if (!Number.isInteger(count)) count = this.length - offset;
        return new ByteArray(this.byteArray.slice(offset, offset + count));
    };

    ByteArray.prototype.viewAt = function viewAt(offset, count) {
        if (!Number.isInteger(count)) count = this.length - offset;
        return new ByteArray(this.byteArray.subarray(offset, offset + count));
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
        for (var i = 0; i < this.length; ++i) s += ("0" + this.byteArray[i].toString(16)).slice(-2);
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

exports.ByteArray = ByteArray;

ByteArray.RAW = ByteEncoding.RAW;
ByteArray.HEX = ByteEncoding.HEX;
ByteArray.BASE64 = ByteEncoding.BASE64;
ByteArray.UTF8 = ByteEncoding.UTF8;

var Enum = function Enum() {
    _classCallCheck(this, Enum);
};

exports.Enum = Enum;

var Integer = (function (_Number) {
    _inherits(Integer, _Number);

    function Integer() {
        _classCallCheck(this, Integer);

        _Number.apply(this, arguments);
    }

    return Integer;
})(Number);

exports.Integer = Integer;

var FieldArray = function FieldArray() {
    _classCallCheck(this, FieldArray);
};

exports.FieldArray = FieldArray;
var FieldTypes = {
    Boolean: Boolean,
    Number: Number,
    Integer: Integer,
    ByteArray: ByteArray,
    Enum: Enum,
    Array: FieldArray,
    String: String,
    Kind: Kind
};
exports.FieldTypes = FieldTypes;

var KindInfo = function KindInfo() {
    _classCallCheck(this, KindInfo);

    this.fields = {};
};

exports.KindInfo = KindInfo;

var KindBuilder = (function () {
    function KindBuilder(ctor, description) {
        _classCallCheck(this, KindBuilder);

        this.ctor = ctor;
        ctor.kindInfo = {
            name: ctor.name,
            description: description,
            fields: {}
        };
    }

    KindBuilder.init = function init(ctor, description) {
        var builder = new KindBuilder(ctor, description);
        return builder;
    };

    KindBuilder.prototype.field = function field(name, description, fieldType) {
        var opts = arguments.length <= 3 || arguments[3] === undefined ? {} : arguments[3];

        var field = opts;
        field.description = description;
        field.fieldType = fieldType;
        this.ctor.kindInfo.fields[name] = field;
        return this;
    };

    KindBuilder.prototype.boolField = function boolField(name, description) {
        var opts = arguments.length <= 2 || arguments[2] === undefined ? {} : arguments[2];

        return this.field(name, description, Boolean, opts);
    };

    KindBuilder.prototype.numberField = function numberField(name, description) {
        var opts = arguments.length <= 2 || arguments[2] === undefined ? {} : arguments[2];

        return this.field(name, description, Number, opts);
    };

    KindBuilder.prototype.integerField = function integerField(name, description) {
        var opts = arguments.length <= 2 || arguments[2] === undefined ? {} : arguments[2];

        return this.field(name, description, Integer, opts);
    };

    KindBuilder.prototype.uint32Field = function uint32Field(name, description) {
        var opts = arguments.length <= 2 || arguments[2] === undefined ? {} : arguments[2];

        opts.minimum = opts.minimum || 0;
        opts.maximum = opts.maximum || 0xFFFFFFFF;
        return this.field(name, description, Integer, opts);
    };

    KindBuilder.prototype.byteField = function byteField(name, description) {
        var opts = arguments.length <= 2 || arguments[2] === undefined ? {} : arguments[2];

        opts.minimum = opts.minimum || 0;
        opts.maximum = opts.maximum || 255;
        return this.field(name, description, Integer, opts);
    };

    KindBuilder.prototype.stringField = function stringField(name, description) {
        var opts = arguments.length <= 2 || arguments[2] === undefined ? {} : arguments[2];

        return this.field(name, description, String, opts);
    };

    KindBuilder.prototype.kindField = function kindField(name, description, kind) {
        var opts = arguments.length <= 3 || arguments[3] === undefined ? {} : arguments[3];

        opts.kind = kind;
        return this.field(name, description, Kind, opts);
    };

    KindBuilder.prototype.enumField = function enumField(name, description, enumm) {
        var opts = arguments.length <= 3 || arguments[3] === undefined ? {} : arguments[3];

        opts.enumMap = new Map();
        for (var idx in enumm) {
            if (1 * idx == idx) opts.enumMap.set(idx, enumm[idx]);
        }
        return this.field(name, description, Enum, opts);
    };

    return KindBuilder;
})();

exports.KindBuilder = KindBuilder;

var Kind = (function () {
    function Kind() {
        _classCallCheck(this, Kind);
    }

    Kind.getKindInfo = function getKindInfo(kind) {
        return kind.constructor.kindInfo;
    };

    Kind.initFields = function initFields(kind) {
        var attributes = arguments.length <= 1 || arguments[1] === undefined ? {} : arguments[1];

        var kindInfo = Kind.getKindInfo(kind);
        for (var id in kindInfo.fields) {
            var field = kindInfo.fields[id];
            var fieldType = field.fieldType;
            var val = undefined;
            if (!field.calculated) {
                if (attributes[id]) val = attributes[id];else if (field['default'] != undefined) val = field['default'];else if (fieldType == String) val = '';else if (fieldType == Number) val = 0;else if (fieldType == Integer) val = field.minimum || 0;else if (fieldType == Boolean) val = false;else if (fieldType == ByteArray) val = new ByteArray();else if (fieldType == Enum) val = field.enumMap.keys[0];else if (fieldType == Kind) {
                    var xx = fieldType.constructor;
                    val = Object.create(xx);
                }
                kind[id] = val;
            }
        }
    };

    return Kind;
})();

exports.Kind = Kind;

var Message = (function () {
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

exports.Message = Message;

var KindMessage = (function (_Message) {
    _inherits(KindMessage, _Message);

    function KindMessage() {
        _classCallCheck(this, KindMessage);

        _Message.apply(this, arguments);
    }

    return KindMessage;
})(Message);

exports.KindMessage = KindMessage;

var window = window || {};

var TaskScheduler = (function () {
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

exports.TaskScheduler = TaskScheduler;

TaskScheduler.BrowserMutationObserver = window["MutationObserver"] || window["WebKitMutationObserver"];
TaskScheduler.hasSetImmediate = typeof setImmediate === 'function';
TaskScheduler.taskQueueCapacity = 1024;

var Channel = (function () {
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
        var _this = this;

        var isResponse = message.header && message.header.isResponse;
        if (!this._active) return;
        if (origin.direction == Direction.IN && !isResponse) throw new Error('Unable to send on IN port');
        this._endPoints.forEach(function (endPoint) {
            if (origin != endPoint) {
                if (endPoint.direction != Direction.OUT || isResponse) {
                    _this._taskScheduler.queueTask(function () {
                        endPoint.handleMessage(message, origin, _this);
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

exports.Channel = Channel;
var Direction;
exports.Direction = Direction;
(function (Direction) {
    Direction[Direction["IN"] = 1] = "IN";
    Direction[Direction["OUT"] = 2] = "OUT";
    Direction[Direction["INOUT"] = 3] = "INOUT";
})(Direction || (exports.Direction = Direction = {}));
;

var EndPoint = (function () {
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
        var _this2 = this;

        this._channels.forEach(function (channel) {
            channel.removeEndPoint(_this2);
        });
        this._channels = [];
    };

    EndPoint.prototype.handleMessage = function handleMessage(message, fromEndPoint, fromChannel) {
        var _this3 = this;

        this._messageListeners.forEach(function (messageListener) {
            messageListener(message, _this3, fromChannel);
        });
    };

    EndPoint.prototype.sendMessage = function sendMessage(message) {
        var _this4 = this;

        this._channels.forEach(function (channel) {
            channel.sendMessage(_this4, message);
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

exports.EndPoint = EndPoint;
var ProtocolTypeBits;
exports.ProtocolTypeBits = ProtocolTypeBits;
(function (ProtocolTypeBits) {
    ProtocolTypeBits[ProtocolTypeBits["PACKET"] = 0] = "PACKET";
    ProtocolTypeBits[ProtocolTypeBits["STREAM"] = 1] = "STREAM";
    ProtocolTypeBits[ProtocolTypeBits["ONEWAY"] = 0] = "ONEWAY";
    ProtocolTypeBits[ProtocolTypeBits["CLIENTSERVER"] = 4] = "CLIENTSERVER";
    ProtocolTypeBits[ProtocolTypeBits["PEER2PEER"] = 6] = "PEER2PEER";
    ProtocolTypeBits[ProtocolTypeBits["UNTYPED"] = 0] = "UNTYPED";
    ProtocolTypeBits[ProtocolTypeBits["TYPED"] = 8] = "TYPED";
})(ProtocolTypeBits || (exports.ProtocolTypeBits = ProtocolTypeBits = {}));

var Protocol = function Protocol() {
    _classCallCheck(this, Protocol);
};

exports.Protocol = Protocol;

Protocol.protocolType = 0;

var ClientServerProtocol = (function (_Protocol) {
    _inherits(ClientServerProtocol, _Protocol);

    function ClientServerProtocol() {
        _classCallCheck(this, ClientServerProtocol);

        _Protocol.apply(this, arguments);
    }

    return ClientServerProtocol;
})(Protocol);

ClientServerProtocol.protocolType = ProtocolTypeBits.CLIENTSERVER | ProtocolTypeBits.TYPED;

var APDU = function APDU() {
    _classCallCheck(this, APDU);
};

var APDUMessage = (function (_Message2) {
    _inherits(APDUMessage, _Message2);

    function APDUMessage() {
        _classCallCheck(this, APDUMessage);

        _Message2.apply(this, arguments);
    }

    return APDUMessage;
})(Message);

var APDUProtocol = (function (_ClientServerProtocol) {
    _inherits(APDUProtocol, _ClientServerProtocol);

    function APDUProtocol() {
        _classCallCheck(this, APDUProtocol);

        _ClientServerProtocol.apply(this, arguments);
    }

    return APDUProtocol;
})(ClientServerProtocol);

var PortInfo = function PortInfo() {
    _classCallCheck(this, PortInfo);

    this.count = 0;
    this.required = false;
};

exports.PortInfo = PortInfo;

var ComponentInfo = function ComponentInfo() {
    _classCallCheck(this, ComponentInfo);

    this.detailLink = '';
    this.category = '';
    this.author = '';
    this.ports = {};
    this.stores = {};
};

exports.ComponentInfo = ComponentInfo;

var StoreInfo = function StoreInfo() {
    _classCallCheck(this, StoreInfo);
};

exports.StoreInfo = StoreInfo;

var ComponentBuilder = (function () {
    function ComponentBuilder(ctor, name, description, category) {
        _classCallCheck(this, ComponentBuilder);

        this.ctor = ctor;
        ctor.componentInfo = {
            name: name || ctor.name,
            description: description,
            detailLink: '',
            category: category,
            author: '',
            ports: {},
            stores: {},
            configKind: Kind,
            defaultConfig: {}
        };
    }

    ComponentBuilder.init = function init(ctor, name, description, category) {
        var builder = new ComponentBuilder(ctor, name, description, category);
        return builder;
    };

    ComponentBuilder.prototype.config = function config(configKind, defaultConfig) {
        this.ctor.componentInfo.configKind = configKind;
        this.ctor.componentInfo.defaultConfig = defaultConfig;
        return this;
    };

    ComponentBuilder.prototype.port = function port(id, description, direction, opts) {
        opts = opts || {};
        this.ctor.componentInfo.ports[id] = {
            direction: direction,
            description: description,
            protocol: opts.protocol,
            count: opts.count,
            required: opts.required
        };
        return this;
    };

    return ComponentBuilder;
})();

exports.ComponentBuilder = ComponentBuilder;
var CryptographicOperation;
exports.CryptographicOperation = CryptographicOperation;
(function (CryptographicOperation) {
    CryptographicOperation[CryptographicOperation["ENCRYPT"] = 0] = "ENCRYPT";
    CryptographicOperation[CryptographicOperation["DECRYPT"] = 1] = "DECRYPT";
    CryptographicOperation[CryptographicOperation["DIGEST"] = 2] = "DIGEST";
    CryptographicOperation[CryptographicOperation["SIGN"] = 3] = "SIGN";
    CryptographicOperation[CryptographicOperation["VERIFY"] = 4] = "VERIFY";
    CryptographicOperation[CryptographicOperation["DERIVE_BITS"] = 5] = "DERIVE_BITS";
    CryptographicOperation[CryptographicOperation["DERIVE_KEY"] = 6] = "DERIVE_KEY";
    CryptographicOperation[CryptographicOperation["IMPORT_KEY"] = 7] = "IMPORT_KEY";
    CryptographicOperation[CryptographicOperation["EXPORT_KEY"] = 8] = "EXPORT_KEY";
    CryptographicOperation[CryptographicOperation["GENERATE_KEY"] = 9] = "GENERATE_KEY";
    CryptographicOperation[CryptographicOperation["WRAP_KEY"] = 10] = "WRAP_KEY";
    CryptographicOperation[CryptographicOperation["UNWRAP_KEY"] = 11] = "UNWRAP_KEY";
})(CryptographicOperation || (exports.CryptographicOperation = CryptographicOperation = {}));

var CryptographicServiceRegistry = (function () {
    function CryptographicServiceRegistry() {
        _classCallCheck(this, CryptographicServiceRegistry);

        this._serviceMap = new Map();
        this._keyServiceMap = new Map();
    }

    CryptographicServiceRegistry.prototype.getService = function getService(algorithm) {
        var algo = algorithm instanceof Object ? algorithm.name : algorithm;
        var service = this._serviceMap.get(algo);
        return { name: algo, instance: service ? new service() : null };
    };

    CryptographicServiceRegistry.prototype.getKeyService = function getKeyService(algorithm) {
        var algo = algorithm instanceof Object ? algorithm.name : algorithm;
        var service = this._keyServiceMap.get(algo);
        return { name: algo, instance: service ? new service() : null };
    };

    CryptographicServiceRegistry.prototype.setService = function setService(algorithm, ctor, opers) {
        ctor.supportedOperations = opers;
        this._serviceMap.set(algorithm, ctor);
    };

    CryptographicServiceRegistry.prototype.setKeyService = function setKeyService(algorithm, ctor, opers) {
        ctor.supportedOperations = opers;
        this._keyServiceMap.set(algorithm, ctor);
    };

    return CryptographicServiceRegistry;
})();

exports.CryptographicServiceRegistry = CryptographicServiceRegistry;

var CryptographicServiceProvider = (function () {
    function CryptographicServiceProvider() {
        _classCallCheck(this, CryptographicServiceProvider);
    }

    CryptographicServiceProvider.registerService = function registerService(name, ctor, opers) {
        CryptographicServiceProvider._registry.setService(name, ctor, opers);
    };

    CryptographicServiceProvider.registerKeyService = function registerKeyService(name, ctor, opers) {
        CryptographicServiceProvider._registry.setKeyService(name, ctor, opers);
    };

    CryptographicServiceProvider.prototype.encrypt = function encrypt(algorithm, key, data) {
        var _registry$getService = this.registry.getService(algorithm);

        var name = _registry$getService.name;
        var instance = _registry$getService.instance;

        return instance && instance.encrypt ? instance.encrypt(name, key, data) : Promise.reject("");
    };

    CryptographicServiceProvider.prototype.decrypt = function decrypt(algorithm, key, data) {
        var _registry$getService2 = this.registry.getService(algorithm);

        var name = _registry$getService2.name;
        var instance = _registry$getService2.instance;

        return instance && instance.decrypt ? instance.decrypt(name, key, data) : Promise.reject("");
    };

    CryptographicServiceProvider.prototype.digest = function digest(algorithm, data) {
        var _registry$getService3 = this.registry.getService(algorithm);

        var name = _registry$getService3.name;
        var instance = _registry$getService3.instance;

        return instance && instance.digest ? instance.digest(name, data) : Promise.reject("");
    };

    CryptographicServiceProvider.prototype.sign = function sign(algorithm, key, data) {
        var _registry$getService4 = this.registry.getService(algorithm);

        var name = _registry$getService4.name;
        var instance = _registry$getService4.instance;

        return instance && instance.sign ? instance.sign(name, key, data) : Promise.reject("");
    };

    CryptographicServiceProvider.prototype.verify = function verify(algorithm, key, signature, data) {
        var _registry$getService5 = this.registry.getService(algorithm);

        var name = _registry$getService5.name;
        var instance = _registry$getService5.instance;

        return instance && instance.verify ? instance.verify(name, key, signature, data) : Promise.reject("");
    };

    CryptographicServiceProvider.prototype.exportKey = function exportKey(format, key) {
        var _registry$getKeyService = this.registry.getKeyService(key.algorithm);

        var name = _registry$getKeyService.name;
        var instance = _registry$getKeyService.instance;

        return instance && instance.exportKey ? instance.exportKey(format, key) : Promise.reject("");
    };

    CryptographicServiceProvider.prototype.generateKey = function generateKey(algorithm, extractable, keyUsages) {
        var _registry$getKeyService2 = this.registry.getKeyService(algorithm);

        var name = _registry$getKeyService2.name;
        var instance = _registry$getKeyService2.instance;

        return instance && instance.generateKey ? instance.generateKey(name, extractable, keyUsages) : Promise.reject("");
    };

    CryptographicServiceProvider.prototype.importKey = function importKey(format, keyData, algorithm, extractable, keyUsages) {
        var _registry$getKeyService3 = this.registry.getKeyService(algorithm);

        var name = _registry$getKeyService3.name;
        var instance = _registry$getKeyService3.instance;

        return instance && instance.importKey ? instance.importKey(format, keyData, name, extractable, keyUsages) : Promise.reject("");
    };

    CryptographicServiceProvider.prototype.deriveKey = function deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        var _registry$getKeyService4 = this.registry.getKeyService(algorithm);

        var name = _registry$getKeyService4.name;
        var instance = _registry$getKeyService4.instance;

        return instance && instance.deriveKey ? instance.deriveKey(name, baseKey, derivedKeyType, extractable, keyUsages) : Promise.reject("");
    };

    CryptographicServiceProvider.prototype.deriveBits = function deriveBits(algorithm, baseKey, length) {
        var _registry$getService6 = this.registry.getService(algorithm);

        var name = _registry$getService6.name;
        var instance = _registry$getService6.instance;

        return instance && instance.deriveBits ? instance.deriveBits(name, baseKey, length) : Promise.reject("");
    };

    CryptographicServiceProvider.prototype.wrapKey = function wrapKey(format, key, wrappingKey, wrapAlgorithm) {
        var _registry$getKeyService5 = this.registry.getKeyService(key.algorithm);

        var name = _registry$getKeyService5.name;
        var instance = _registry$getKeyService5.instance;

        return instance && instance.wrapKey ? instance.wrapKey(format, key, wrappingKey, wrapAlgorithm) : Promise.reject("");
    };

    CryptographicServiceProvider.prototype.unwrapKey = function unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        var _registry$getKeyService6 = this.registry.getKeyService(unwrapAlgorithm);

        var name = _registry$getKeyService6.name;
        var instance = _registry$getKeyService6.instance;

        return instance && instance.unwrapKey ? instance.unwrapKey(format, wrappedKey, unwrappingKey, name, unwrappedKeyAlgorithm, extractable, keyUsages) : Promise.reject("");
    };

    _createClass(CryptographicServiceProvider, [{
        key: 'registry',
        get: function get() {
            return CryptographicServiceProvider._registry;
        }
    }]);

    return CryptographicServiceProvider;
})();

exports.CryptographicServiceProvider = CryptographicServiceProvider;

CryptographicServiceProvider._registry = new CryptographicServiceRegistry();

var WebCryptoService = (function () {
    function WebCryptoService() {
        _classCallCheck(this, WebCryptoService);
    }

    WebCryptoService.prototype.encrypt = function encrypt(algorithm, key, data) {
        return new Promise(function (resolve, reject) {
            WebCryptoService.subtle.encrypt(algorithm, key, data.backingArray).then(function (res) {
                resolve(new ByteArray(res));
            })['catch'](function (err) {
                reject(err);
            });
        });
    };

    WebCryptoService.prototype.decrypt = function decrypt(algorithm, key, data) {
        return new Promise(function (resolve, reject) {
            WebCryptoService.subtle.decrypt(algorithm, key, data.backingArray).then(function (res) {
                resolve(new ByteArray(res));
            })['catch'](function (err) {
                reject(err);
            });
        });
    };

    WebCryptoService.prototype.digest = function digest(algorithm, data) {
        return new Promise(function (resolve, reject) {
            WebCryptoService.subtle.digest(algorithm, data.backingArray).then(function (res) {
                resolve(new ByteArray(res));
            })['catch'](function (err) {
                reject(err);
            });
        });
    };

    WebCryptoService.prototype.exportKey = function exportKey(format, key) {
        return new Promise(function (resolve, reject) {
            WebCryptoService.subtle.exportKey(format, key).then(function (res) {
                resolve(new ByteArray(res));
            })['catch'](function (err) {
                reject(err);
            });
        });
    };

    WebCryptoService.prototype.generateKey = function generateKey(algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {});
    };

    WebCryptoService.prototype.importKey = function importKey(format, keyData, algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            WebCryptoService.subtle.importKey(format, keyData.backingArray, algorithm, extractable, keyUsages).then(function (res) {
                resolve(res);
            })['catch'](function (err) {
                reject(err);
            });
        });
    };

    WebCryptoService.prototype.sign = function sign(algorithm, key, data) {
        return new Promise(function (resolve, reject) {
            WebCryptoService.subtle.sign(algorithm, key, data.backingArray).then(function (res) {
                resolve(new ByteArray(res));
            })['catch'](function (err) {
                reject(err);
            });
        });
    };

    WebCryptoService.prototype.verify = function verify(algorithm, key, signature, data) {
        return new Promise(function (resolve, reject) {
            WebCryptoService.subtle.verify(algorithm, key, signature.backingArray, data.backingArray).then(function (res) {
                resolve(new ByteArray(res));
            })['catch'](function (err) {
                reject(err);
            });
        });
    };

    _createClass(WebCryptoService, null, [{
        key: 'subtle',
        get: function get() {
            var subtle = WebCryptoService._subtle || window && window.crypto.subtle || msrcrypto;
            if (!WebCryptoService._subtle) WebCryptoService._subtle = subtle;
            return subtle;
        }
    }]);

    return WebCryptoService;
})();

exports.WebCryptoService = WebCryptoService;

if (WebCryptoService.subtle) {
    CryptographicServiceProvider.registerService('AES-CBC', WebCryptoService, [CryptographicOperation.ENCRYPT, CryptographicOperation.DECRYPT]);
    CryptographicServiceProvider.registerService('AES-GCM', WebCryptoService, [CryptographicOperation.ENCRYPT, CryptographicOperation.DECRYPT]);
}

var DESSecretKey = (function () {
    function DESSecretKey(keyMaterial, algorithm, extractable, usages) {
        _classCallCheck(this, DESSecretKey);

        this._keyMaterial = keyMaterial;
        this._algorithm = algorithm;
        this._extractable = extractable;
        this._type = 'secret';
        this._usages = usages;
        Object.freeze(this._usages);
    }

    _createClass(DESSecretKey, [{
        key: 'algorithm',
        get: function get() {
            return this._algorithm;
        }
    }, {
        key: 'extractable',
        get: function get() {
            return this._extractable;
        }
    }, {
        key: 'type',
        get: function get() {
            return this._type;
        }
    }, {
        key: 'usages',
        get: function get() {
            return Array.from(this._usages);
        }
    }, {
        key: 'keyMaterial',
        get: function get() {
            return this._keyMaterial;
        }
    }]);

    return DESSecretKey;
})();

var DESCryptographicService = (function () {
    function DESCryptographicService() {
        _classCallCheck(this, DESCryptographicService);
    }

    DESCryptographicService.prototype.encrypt = function encrypt(algorithm, key, data) {
        var _this5 = this;

        return new Promise(function (resolve, reject) {
            var desKey = key;
            resolve(new ByteArray(_this5.des(desKey.keyMaterial.backingArray, data.backingArray, 1, 0)));
        });
    };

    DESCryptographicService.prototype.decrypt = function decrypt(algorithm, key, data) {
        var _this6 = this;

        return new Promise(function (resolve, reject) {
            var desKey = key;
            resolve(new ByteArray(_this6.des(desKey.keyMaterial.backingArray, data.backingArray, 0, 0)));
        });
    };

    DESCryptographicService.prototype.importKey = function importKey(format, keyData, algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            var desKey = new DESSecretKey(keyData, algorithm, extractable, keyUsages);
            resolve(desKey);
        });
    };

    DESCryptographicService.prototype.sign = function sign(algorithm, key, data) {
        var _this7 = this;

        return new Promise(function (resolve, reject) {
            var desKey = key;
            resolve(new ByteArray(_this7.des(desKey.keyMaterial.backingArray, data.backingArray, 0, 0)));
        });
    };

    DESCryptographicService.prototype.des = function des(key, message, encrypt, mode, iv, padding) {
        function des_createKeys(key) {
            var desPC = DESCryptographicService.desPC;
            if (!desPC) {
                desPC = DESCryptographicService.desPC = {
                    pc2bytes0: new Uint32Array([0, 0x4, 0x20000000, 0x20000004, 0x10000, 0x10004, 0x20010000, 0x20010004, 0x200, 0x204, 0x20000200, 0x20000204, 0x10200, 0x10204, 0x20010200, 0x20010204]),
                    pc2bytes1: new Uint32Array([0, 0x1, 0x100000, 0x100001, 0x4000000, 0x4000001, 0x4100000, 0x4100001, 0x100, 0x101, 0x100100, 0x100101, 0x4000100, 0x4000101, 0x4100100, 0x4100101]),
                    pc2bytes2: new Uint32Array([0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808, 0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808]),
                    pc2bytes3: new Uint32Array([0, 0x200000, 0x8000000, 0x8200000, 0x2000, 0x202000, 0x8002000, 0x8202000, 0x20000, 0x220000, 0x8020000, 0x8220000, 0x22000, 0x222000, 0x8022000, 0x8222000]),
                    pc2bytes4: new Uint32Array([0, 0x40000, 0x10, 0x40010, 0, 0x40000, 0x10, 0x40010, 0x1000, 0x41000, 0x1010, 0x41010, 0x1000, 0x41000, 0x1010, 0x41010]),
                    pc2bytes5: new Uint32Array([0, 0x400, 0x20, 0x420, 0, 0x400, 0x20, 0x420, 0x2000000, 0x2000400, 0x2000020, 0x2000420, 0x2000000, 0x2000400, 0x2000020, 0x2000420]),
                    pc2bytes6: new Uint32Array([0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002, 0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002]),
                    pc2bytes7: new Uint32Array([0, 0x10000, 0x800, 0x10800, 0x20000000, 0x20010000, 0x20000800, 0x20010800, 0x20000, 0x30000, 0x20800, 0x30800, 0x20020000, 0x20030000, 0x20020800, 0x20030800]),
                    pc2bytes8: new Uint32Array([0, 0x40000, 0, 0x40000, 0x2, 0x40002, 0x2, 0x40002, 0x2000000, 0x2040000, 0x2000000, 0x2040000, 0x2000002, 0x2040002, 0x2000002, 0x2040002]),
                    pc2bytes9: new Uint32Array([0, 0x10000000, 0x8, 0x10000008, 0, 0x10000000, 0x8, 0x10000008, 0x400, 0x10000400, 0x408, 0x10000408, 0x400, 0x10000400, 0x408, 0x10000408]),
                    pc2bytes10: new Uint32Array([0, 0x20, 0, 0x20, 0x100000, 0x100020, 0x100000, 0x100020, 0x2000, 0x2020, 0x2000, 0x2020, 0x102000, 0x102020, 0x102000, 0x102020]),
                    pc2bytes11: new Uint32Array([0, 0x1000000, 0x200, 0x1000200, 0x200000, 0x1200000, 0x200200, 0x1200200, 0x4000000, 0x5000000, 0x4000200, 0x5000200, 0x4200000, 0x5200000, 0x4200200, 0x5200200]),
                    pc2bytes12: new Uint32Array([0, 0x1000, 0x8000000, 0x8001000, 0x80000, 0x81000, 0x8080000, 0x8081000, 0x10, 0x1010, 0x8000010, 0x8001010, 0x80010, 0x81010, 0x8080010, 0x8081010]),
                    pc2bytes13: new Uint32Array([0, 0x4, 0x100, 0x104, 0, 0x4, 0x100, 0x104, 0x1, 0x5, 0x101, 0x105, 0x1, 0x5, 0x101, 0x105])
                };
            }
            var iterations = key.length > 8 ? 3 : 1;
            var keys = new Uint32Array(32 * iterations);
            var shifts = [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0];
            var lefttemp,
                righttemp,
                m = 0,
                n = 0,
                temp;
            for (var j = 0; j < iterations; j++) {
                left = key[m++] << 24 | key[m++] << 16 | key[m++] << 8 | key[m++];
                right = key[m++] << 24 | key[m++] << 16 | key[m++] << 8 | key[m++];
                temp = (left >>> 4 ^ right) & 0x0f0f0f0f;
                right ^= temp;
                left ^= temp << 4;
                temp = (right >>> -16 ^ left) & 0x0000ffff;
                left ^= temp;
                right ^= temp << -16;
                temp = (left >>> 2 ^ right) & 0x33333333;
                right ^= temp;
                left ^= temp << 2;
                temp = (right >>> -16 ^ left) & 0x0000ffff;
                left ^= temp;
                right ^= temp << -16;
                temp = (left >>> 1 ^ right) & 0x55555555;
                right ^= temp;
                left ^= temp << 1;
                temp = (right >>> 8 ^ left) & 0x00ff00ff;
                left ^= temp;
                right ^= temp << 8;
                temp = (left >>> 1 ^ right) & 0x55555555;
                right ^= temp;
                left ^= temp << 1;
                temp = left << 8 | right >>> 20 & 0x000000f0;
                left = right << 24 | right << 8 & 0xff0000 | right >>> 8 & 0xff00 | right >>> 24 & 0xf0;
                right = temp;
                for (var i = 0; i < shifts.length; i++) {
                    if (shifts[i]) {
                        left = left << 2 | left >>> 26;
                        right = right << 2 | right >>> 26;
                    } else {
                        left = left << 1 | left >>> 27;
                        right = right << 1 | right >>> 27;
                    }
                    left &= -0xf;
                    right &= -0xf;
                    lefttemp = desPC.pc2bytes0[left >>> 28] | desPC.pc2bytes1[left >>> 24 & 0xf] | desPC.pc2bytes2[left >>> 20 & 0xf] | desPC.pc2bytes3[left >>> 16 & 0xf] | desPC.pc2bytes4[left >>> 12 & 0xf] | desPC.pc2bytes5[left >>> 8 & 0xf] | desPC.pc2bytes6[left >>> 4 & 0xf];
                    righttemp = desPC.pc2bytes7[right >>> 28] | desPC.pc2bytes8[right >>> 24 & 0xf] | desPC.pc2bytes9[right >>> 20 & 0xf] | desPC.pc2bytes10[right >>> 16 & 0xf] | desPC.pc2bytes11[right >>> 12 & 0xf] | desPC.pc2bytes12[right >>> 8 & 0xf] | desPC.pc2bytes13[right >>> 4 & 0xf];
                    temp = (righttemp >>> 16 ^ lefttemp) & 0x0000ffff;
                    keys[n++] = lefttemp ^ temp;
                    keys[n++] = righttemp ^ temp << 16;
                }
            }
            return keys;
        }
        var desSP = DESCryptographicService.desSP;
        if (desSP == undefined) {
            desSP = DESCryptographicService.desSP = {
                spfunction1: new Uint32Array([0x1010400, 0, 0x10000, 0x1010404, 0x1010004, 0x10404, 0x4, 0x10000, 0x400, 0x1010400, 0x1010404, 0x400, 0x1000404, 0x1010004, 0x1000000, 0x4, 0x404, 0x1000400, 0x1000400, 0x10400, 0x10400, 0x1010000, 0x1010000, 0x1000404, 0x10004, 0x1000004, 0x1000004, 0x10004, 0, 0x404, 0x10404, 0x1000000, 0x10000, 0x1010404, 0x4, 0x1010000, 0x1010400, 0x1000000, 0x1000000, 0x400, 0x1010004, 0x10000, 0x10400, 0x1000004, 0x400, 0x4, 0x1000404, 0x10404, 0x1010404, 0x10004, 0x1010000, 0x1000404, 0x1000004, 0x404, 0x10404, 0x1010400, 0x404, 0x1000400, 0x1000400, 0, 0x10004, 0x10400, 0, 0x1010004]),
                spfunction2: new Uint32Array([-0x7fef7fe0, -0x7fff8000, 0x8000, 0x108020, 0x100000, 0x20, -0x7fefffe0, -0x7fff7fe0, -0x7fffffe0, -0x7fef7fe0, -0x7fef8000, -0x80000000, -0x7fff8000, 0x100000, 0x20, -0x7fefffe0, 0x108000, 0x100020, -0x7fff7fe0, 0, -0x80000000, 0x8000, 0x108020, -0x7ff00000, 0x100020, -0x7fffffe0, 0, 0x108000, 0x8020, -0x7fef8000, -0x7ff00000, 0x8020, 0, 0x108020, -0x7fefffe0, 0x100000, -0x7fff7fe0, -0x7ff00000, -0x7fef8000, 0x8000, -0x7ff00000, -0x7fff8000, 0x20, -0x7fef7fe0, 0x108020, 0x20, 0x8000, -0x80000000, 0x8020, -0x7fef8000, 0x100000, -0x7fffffe0, 0x100020, -0x7fff7fe0, -0x7fffffe0, 0x100020, 0x108000, 0, -0x7fff8000, 0x8020, -0x80000000, -0x7fefffe0, -0x7fef7fe0, 0x108000]),
                spfunction3: new Uint32Array([0x208, 0x8020200, 0, 0x8020008, 0x8000200, 0, 0x20208, 0x8000200, 0x20008, 0x8000008, 0x8000008, 0x20000, 0x8020208, 0x20008, 0x8020000, 0x208, 0x8000000, 0x8, 0x8020200, 0x200, 0x20200, 0x8020000, 0x8020008, 0x20208, 0x8000208, 0x20200, 0x20000, 0x8000208, 0x8, 0x8020208, 0x200, 0x8000000, 0x8020200, 0x8000000, 0x20008, 0x208, 0x20000, 0x8020200, 0x8000200, 0, 0x200, 0x20008, 0x8020208, 0x8000200, 0x8000008, 0x200, 0, 0x8020008, 0x8000208, 0x20000, 0x8000000, 0x8020208, 0x8, 0x20208, 0x20200, 0x8000008, 0x8020000, 0x8000208, 0x208, 0x8020000, 0x20208, 0x8, 0x8020008, 0x20200]),
                spfunction4: new Uint32Array([0x802001, 0x2081, 0x2081, 0x80, 0x802080, 0x800081, 0x800001, 0x2001, 0, 0x802000, 0x802000, 0x802081, 0x81, 0, 0x800080, 0x800001, 0x1, 0x2000, 0x800000, 0x802001, 0x80, 0x800000, 0x2001, 0x2080, 0x800081, 0x1, 0x2080, 0x800080, 0x2000, 0x802080, 0x802081, 0x81, 0x800080, 0x800001, 0x802000, 0x802081, 0x81, 0, 0, 0x802000, 0x2080, 0x800080, 0x800081, 0x1, 0x802001, 0x2081, 0x2081, 0x80, 0x802081, 0x81, 0x1, 0x2000, 0x800001, 0x2001, 0x802080, 0x800081, 0x2001, 0x2080, 0x800000, 0x802001, 0x80, 0x800000, 0x2000, 0x802080]),
                spfunction5: new Uint32Array([0x100, 0x2080100, 0x2080000, 0x42000100, 0x80000, 0x100, 0x40000000, 0x2080000, 0x40080100, 0x80000, 0x2000100, 0x40080100, 0x42000100, 0x42080000, 0x80100, 0x40000000, 0x2000000, 0x40080000, 0x40080000, 0, 0x40000100, 0x42080100, 0x42080100, 0x2000100, 0x42080000, 0x40000100, 0, 0x42000000, 0x2080100, 0x2000000, 0x42000000, 0x80100, 0x80000, 0x42000100, 0x100, 0x2000000, 0x40000000, 0x2080000, 0x42000100, 0x40080100, 0x2000100, 0x40000000, 0x42080000, 0x2080100, 0x40080100, 0x100, 0x2000000, 0x42080000, 0x42080100, 0x80100, 0x42000000, 0x42080100, 0x2080000, 0, 0x40080000, 0x42000000, 0x80100, 0x2000100, 0x40000100, 0x80000, 0, 0x40080000, 0x2080100, 0x40000100]),
                spfunction6: new Uint32Array([0x20000010, 0x20400000, 0x4000, 0x20404010, 0x20400000, 0x10, 0x20404010, 0x400000, 0x20004000, 0x404010, 0x400000, 0x20000010, 0x400010, 0x20004000, 0x20000000, 0x4010, 0, 0x400010, 0x20004010, 0x4000, 0x404000, 0x20004010, 0x10, 0x20400010, 0x20400010, 0, 0x404010, 0x20404000, 0x4010, 0x404000, 0x20404000, 0x20000000, 0x20004000, 0x10, 0x20400010, 0x404000, 0x20404010, 0x400000, 0x4010, 0x20000010, 0x400000, 0x20004000, 0x20000000, 0x4010, 0x20000010, 0x20404010, 0x404000, 0x20400000, 0x404010, 0x20404000, 0, 0x20400010, 0x10, 0x4000, 0x20400000, 0x404010, 0x4000, 0x400010, 0x20004010, 0, 0x20404000, 0x20000000, 0x400010, 0x20004010]),
                spfunction7: new Uint32Array([0x200000, 0x4200002, 0x4000802, 0, 0x800, 0x4000802, 0x200802, 0x4200800, 0x4200802, 0x200000, 0, 0x4000002, 0x2, 0x4000000, 0x4200002, 0x802, 0x4000800, 0x200802, 0x200002, 0x4000800, 0x4000002, 0x4200000, 0x4200800, 0x200002, 0x4200000, 0x800, 0x802, 0x4200802, 0x200800, 0x2, 0x4000000, 0x200800, 0x4000000, 0x200800, 0x200000, 0x4000802, 0x4000802, 0x4200002, 0x4200002, 0x2, 0x200002, 0x4000000, 0x4000800, 0x200000, 0x4200800, 0x802, 0x200802, 0x4200800, 0x802, 0x4000002, 0x4200802, 0x4200000, 0x200800, 0, 0x2, 0x4200802, 0, 0x200802, 0x4200000, 0x800, 0x4000002, 0x4000800, 0x800, 0x200002]),
                spfunction8: new Uint32Array([0x10001040, 0x1000, 0x40000, 0x10041040, 0x10000000, 0x10001040, 0x40, 0x10000000, 0x40040, 0x10040000, 0x10041040, 0x41000, 0x10041000, 0x41040, 0x1000, 0x40, 0x10040000, 0x10000040, 0x10001000, 0x1040, 0x41000, 0x40040, 0x10040040, 0x10041000, 0x1040, 0, 0, 0x10040040, 0x10000040, 0x10001000, 0x41040, 0x40000, 0x41040, 0x40000, 0x10041000, 0x1000, 0x40, 0x10040040, 0x1000, 0x41040, 0x10001000, 0x40, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x40000, 0x10001040, 0, 0x10041040, 0x40040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0, 0x10041040, 0x41000, 0x41000, 0x1040, 0x1040, 0x40040, 0x10000000, 0x10041000])
            };
        }
        var keys = des_createKeys(key);
        var m = 0,
            i,
            j,
            temp,
            left,
            right,
            looping;
        var cbcleft, cbcleft2, cbcright, cbcright2;
        var len = message.length;
        var iterations = keys.length == 32 ? 3 : 9;
        if (iterations == 3) {
            looping = encrypt ? [0, 32, 2] : [30, -2, -2];
        } else {
            looping = encrypt ? [0, 32, 2, 62, 30, -2, 64, 96, 2] : [94, 62, -2, 32, 64, 2, 30, -2, -2];
        }
        if (padding != undefined && padding != 4) {
            var unpaddedMessage = message;
            var pad = 8 - len % 8;
            message = new Uint8Array(len + 8);
            message.set(unpaddedMessage, 0);
            switch (padding) {
                case 0:
                    message.set(new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), len);
                    break;
                case 1:
                    {
                        message.set(new Uint8Array([pad, pad, pad, pad, pad, pad, pad, pad]), 8);
                        if (pad == 8) len += 8;
                        break;
                    }
                case 2:
                    message.set(new Uint8Array([0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20]), 8);
                    break;
            }
            len += 8 - len % 8;
        }
        var result = new Uint8Array(len);
        if (mode == 1) {
            var m = 0;
            cbcleft = iv[m++] << 24 | iv[m++] << 16 | iv[m++] << 8 | iv[m++];
            cbcright = iv[m++] << 24 | iv[m++] << 16 | iv[m++] << 8 | iv[m++];
        }
        var rm = 0;
        while (m < len) {
            left = message[m++] << 24 | message[m++] << 16 | message[m++] << 8 | message[m++];
            right = message[m++] << 24 | message[m++] << 16 | message[m++] << 8 | message[m++];
            if (mode == 1) {
                if (encrypt) {
                    left ^= cbcleft;
                    right ^= cbcright;
                } else {
                    cbcleft2 = cbcleft;
                    cbcright2 = cbcright;
                    cbcleft = left;
                    cbcright = right;
                }
            }
            temp = (left >>> 4 ^ right) & 0x0f0f0f0f;
            right ^= temp;
            left ^= temp << 4;
            temp = (left >>> 16 ^ right) & 0x0000ffff;
            right ^= temp;
            left ^= temp << 16;
            temp = (right >>> 2 ^ left) & 0x33333333;
            left ^= temp;
            right ^= temp << 2;
            temp = (right >>> 8 ^ left) & 0x00ff00ff;
            left ^= temp;
            right ^= temp << 8;
            temp = (left >>> 1 ^ right) & 0x55555555;
            right ^= temp;
            left ^= temp << 1;
            left = left << 1 | left >>> 31;
            right = right << 1 | right >>> 31;
            for (j = 0; j < iterations; j += 3) {
                var endloop = looping[j + 1];
                var loopinc = looping[j + 2];
                for (i = looping[j]; i != endloop; i += loopinc) {
                    var right1 = right ^ keys[i];
                    var right2 = (right >>> 4 | right << 28) ^ keys[i + 1];
                    temp = left;
                    left = right;
                    right = temp ^ (desSP.spfunction2[right1 >>> 24 & 0x3f] | desSP.spfunction4[right1 >>> 16 & 0x3f] | desSP.spfunction6[right1 >>> 8 & 0x3f] | desSP.spfunction8[right1 & 0x3f] | desSP.spfunction1[right2 >>> 24 & 0x3f] | desSP.spfunction3[right2 >>> 16 & 0x3f] | desSP.spfunction5[right2 >>> 8 & 0x3f] | desSP.spfunction7[right2 & 0x3f]);
                }
                temp = left;
                left = right;
                right = temp;
            }
            left = left >>> 1 | left << 31;
            right = right >>> 1 | right << 31;
            temp = (left >>> 1 ^ right) & 0x55555555;
            right ^= temp;
            left ^= temp << 1;
            temp = (right >>> 8 ^ left) & 0x00ff00ff;
            left ^= temp;
            right ^= temp << 8;
            temp = (right >>> 2 ^ left) & 0x33333333;
            left ^= temp;
            right ^= temp << 2;
            temp = (left >>> 16 ^ right) & 0x0000ffff;
            right ^= temp;
            left ^= temp << 16;
            temp = (left >>> 4 ^ right) & 0x0f0f0f0f;
            right ^= temp;
            left ^= temp << 4;
            if (mode == 1) {
                if (encrypt) {
                    cbcleft = left;
                    cbcright = right;
                } else {
                    left ^= cbcleft2;
                    right ^= cbcright2;
                }
            }
            result.set(new Uint8Array([left >>> 24 & 0xff, left >>> 16 & 0xff, left >>> 8 & 0xff, left & 0xff, right >>> 24 & 0xff, right >>> 16 & 0xff, right >>> 8 & 0xff, right & 0xff]), rm);
            rm += 8;
        }
        return result;
    };

    return DESCryptographicService;
})();

exports.DESCryptographicService = DESCryptographicService;

CryptographicServiceProvider.registerService('DES-ECB', DESCryptographicService, [CryptographicOperation.ENCRYPT, CryptographicOperation.ENCRYPT, CryptographicOperation.DECRYPT, CryptographicOperation.IMPORT_KEY]);

exports.Container = _aureliaDependencyInjection.Container;
exports.inject = _aureliaDependencyInjection.autoinject;

var EventHub = (function () {
    function EventHub() {
        _classCallCheck(this, EventHub);

        this._eventAggregator = new _aureliaEventAggregator.EventAggregator();
    }

    EventHub.prototype.publish = function publish(event, data) {
        this._eventAggregator.publish(event, data);
    };

    EventHub.prototype.subscribe = function subscribe(event, handler) {
        return this._eventAggregator.subscribe(event, handler);
    };

    EventHub.prototype.subscribeOnce = function subscribeOnce(event, handler) {
        return this._eventAggregator.subscribeOnce(event, handler);
    };

    return EventHub;
})();

exports.EventHub = EventHub;

var Port = (function () {
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

exports.Port = Port;

var PublicPort = (function (_Port) {
    _inherits(PublicPort, _Port);

    function PublicPort(owner, endPoint, attributes) {
        var _this8 = this;

        _classCallCheck(this, PublicPort);

        _Port.call(this, owner, endPoint, attributes);
        var proxyDirection = this._endPoint.direction == Direction.IN ? Direction.OUT : this._endPoint.direction == Direction.OUT ? Direction.IN : Direction.INOUT;
        this.proxyEndPoint = new EndPoint(this._endPoint.id, proxyDirection);
        this.proxyEndPoint.onMessage(function (message) {
            _this8._endPoint.handleMessage(message, _this8.proxyEndPoint, _this8.proxyChannel);
        });
        this._endPoint.onMessage(function (message) {
            _this8.proxyEndPoint.sendMessage(message);
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

exports.PublicPort = PublicPort;

var Node = (function (_EventHub) {
    _inherits(Node, _EventHub);

    function Node(owner) {
        var _this9 = this;

        var attributes = arguments.length <= 1 || arguments[1] === undefined ? {} : arguments[1];

        _classCallCheck(this, Node);

        _EventHub.call(this);
        this._owner = owner;
        this._id = attributes.id || '';
        this._component = attributes.component;
        this._initialData = attributes.initialData || {};
        this._ports = new Map();
        this.metadata = attributes.metadata || {};
        Object.keys(attributes.ports || {}).forEach(function (id) {
            _this9.addPlaceholderPort(id, attributes.ports[id]);
        });
    }

    Node.prototype.toObject = function toObject(opts) {
        var node = {
            id: this.id,
            component: this._component,
            initialData: this._initialData,
            ports: {},
            metadata: this.metadata
        };
        this._ports.forEach(function (port, id) {
            node.ports[id] = port.toObject();
        });
        return node;
    };

    Node.prototype.updatePorts = function updatePorts(endPoints) {
        var _this10 = this;

        var currentPorts = this._ports;
        var newPorts = new Map();
        endPoints.forEach(function (ep) {
            var id = ep.id;
            if (currentPorts.has(id)) {
                var port = currentPorts.get(id);
                port.endPoint = ep;
                newPorts.set(id, port);
                currentPorts['delete'](id);
            } else {
                var port = new Port(_this10, ep, { id: id, direction: ep.direction });
                newPorts.set(id, port);
            }
        });
        this._ports = newPorts;
    };

    Node.prototype.addPlaceholderPort = function addPlaceholderPort(id, attributes) {
        attributes["id"] = id;
        var port = new Port(this, null, attributes);
        this._ports.set(id, port);
        return port;
    };

    Node.prototype.getPortArray = function getPortArray() {
        var xports = [];
        this._ports.forEach(function (port, id) {
            xports.push(port);
        });
        return xports;
    };

    Node.prototype.getPortByID = function getPortByID(id) {
        return this._ports.get(id);
    };

    Node.prototype.identifyPort = function identifyPort(id, protocolID) {
        var port;
        if (id) port = this._ports.get(id);else if (protocolID) {
            this._ports.forEach(function (p, id) {
                if (p.protocolID == protocolID) port = p;
            }, this);
        }
        return port;
    };

    Node.prototype.removePort = function removePort(id) {
        return this._ports['delete'](id);
    };

    Node.prototype.loadComponent = function loadComponent(factory) {
        this.unloadComponent();
        var ctx = this._context = factory.createContext(this._component, this._initialData);
        ctx.node = this;
        return ctx.load();
    };

    Node.prototype.unloadComponent = function unloadComponent() {
        if (this._context) {
            this._context.release();
            this._context = null;
        }
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
    }, {
        key: 'ports',
        get: function get() {
            return this._ports;
        }
    }, {
        key: 'context',
        get: function get() {
            return this._context;
        }
    }]);

    return Node;
})(EventHub);

exports.Node = Node;
var RunState;
exports.RunState = RunState;
(function (RunState) {
    RunState[RunState["NEWBORN"] = 0] = "NEWBORN";
    RunState[RunState["LOADING"] = 1] = "LOADING";
    RunState[RunState["LOADED"] = 2] = "LOADED";
    RunState[RunState["READY"] = 3] = "READY";
    RunState[RunState["RUNNING"] = 4] = "RUNNING";
    RunState[RunState["PAUSED"] = 5] = "PAUSED";
})(RunState || (exports.RunState = RunState = {}));

var RuntimeContext = (function () {
    function RuntimeContext(factory, container, id, config) {
        var deps = arguments.length <= 4 || arguments[4] === undefined ? [] : arguments[4];

        _classCallCheck(this, RuntimeContext);

        this._runState = RunState.NEWBORN;
        this._factory = factory;
        this._id = id;
        this._config = config;
        this._container = container;
        for (var i in deps) {
            if (!this._container.hasResolver(deps[i])) this._container.registerSingleton(deps[i], deps[i]);
        }
    }

    RuntimeContext.prototype.load = function load() {
        var _this11 = this;

        var me = this;
        this._instance = null;
        return new Promise(function (resolve, reject) {
            me._runState = RunState.LOADING;
            _this11._factory.loadComponent(_this11, _this11._id).then(function (instance) {
                me._instance = instance;
                me.setRunState(RunState.LOADED);
                resolve();
            })['catch'](function (err) {
                me._runState = RunState.NEWBORN;
                reject(err);
            });
        });
    };

    RuntimeContext.prototype.inState = function inState(states) {
        return new Set(states).has(this._runState);
    };

    RuntimeContext.prototype.setRunState = function setRunState(runState) {
        var inst = this.instance;
        switch (runState) {
            case RunState.LOADED:
                if (this.inState([RunState.READY, RunState.RUNNING, RunState.PAUSED])) {
                    if (inst.teardown) {
                        inst.teardown();
                        this._instance = null;
                    }
                }
                break;
            case RunState.READY:
                if (this.inState([RunState.LOADED])) {
                    var endPoints = [];
                    if (inst.initialize) endPoints = this.instance.initialize(this._config);
                    if (this._node) this._node.updatePorts(endPoints);
                } else if (this.inState([RunState.RUNNING, RunState.PAUSED])) {
                    if (inst.stop) this.instance.stop();
                } else throw new Error('Component cannot be initialized, not loaded');
                break;
            case RunState.RUNNING:
                if (this.inState([RunState.READY, RunState.RUNNING])) {
                    if (inst.start) this.instance.start();
                } else if (this.inState([RunState.PAUSED])) {
                    if (inst.resume) this.instance.resume();
                } else throw new Error('Component cannot be started, not ready');
                break;
            case RunState.PAUSED:
                if (this.inState([RunState.RUNNING])) {
                    if (inst.pause) this.instance.pause();
                } else if (this.inState([RunState.PAUSED])) {} else throw new Error('Component cannot be paused');
                break;
        }
        this._runState = runState;
    };

    RuntimeContext.prototype.release = function release() {
        this._instance = null;
        this._factory = null;
    };

    _createClass(RuntimeContext, [{
        key: 'node',
        get: function get() {
            return this._node;
        },
        set: function set(node) {
            this._node = node;
            this._container.registerInstance(Node, this);
        }
    }, {
        key: 'instance',
        get: function get() {
            return this._instance;
        }
    }, {
        key: 'container',
        get: function get() {
            return this._container;
        }
    }, {
        key: 'runState',
        get: function get() {
            return this._runState;
        }
    }]);

    return RuntimeContext;
})();

exports.RuntimeContext = RuntimeContext;

;

var ModuleRegistryEntry = function ModuleRegistryEntry(address) {
    _classCallCheck(this, ModuleRegistryEntry);
};

var SystemModuleLoader = (function () {
    function SystemModuleLoader() {
        _classCallCheck(this, SystemModuleLoader);

        this.moduleRegistry = new Map();
    }

    SystemModuleLoader.prototype.getOrCreateModuleRegistryEntry = function getOrCreateModuleRegistryEntry(address) {
        return this.moduleRegistry[address] || (this.moduleRegistry[address] = new ModuleRegistryEntry(address));
    };

    SystemModuleLoader.prototype.loadModule = function loadModule(id) {
        var _this12 = this;

        var newId = System.normalizeSync(id);
        var existing = this.moduleRegistry[newId];
        if (existing) {
            return Promise.resolve(existing);
        }
        return System['import'](newId).then(function (m) {
            _this12.moduleRegistry[newId] = m;
            return m;
        });
    };

    return SystemModuleLoader;
})();

exports.SystemModuleLoader = SystemModuleLoader;

var ComponentFactory = (function () {
    function ComponentFactory(container, loader) {
        _classCallCheck(this, ComponentFactory);

        this._loader = loader;
        this._container = container || new _aureliaDependencyInjection.Container();
        this._components = new Map();
        this._components.set(undefined, Object);
        this._components.set("", Object);
    }

    ComponentFactory.prototype.createContext = function createContext(id, config) {
        var deps = arguments.length <= 2 || arguments[2] === undefined ? [] : arguments[2];

        var childContainer = this._container.createChild();
        return new RuntimeContext(this, childContainer, id, config, deps);
    };

    ComponentFactory.prototype.getChildContainer = function getChildContainer() {
        return;
    };

    ComponentFactory.prototype.loadComponent = function loadComponent(ctx, id) {
        var _this13 = this;

        var createComponent = function createComponent(ctor) {
            var newInstance = ctx.container.invoke(ctor);
            return newInstance;
        };
        var me = this;
        return new Promise(function (resolve, reject) {
            var ctor = _this13.get(id);
            if (ctor) {
                resolve(createComponent(ctor));
            } else if (_this13._loader) {
                _this13._loader.loadModule(id).then(function (ctor) {
                    me._components.set(id, ctor);
                    resolve(createComponent(ctor));
                })['catch'](function (e) {
                    reject('ComponentFactory: Unable to load component "' + id + '" - ' + e);
                });
            } else {
                reject('ComponentFactory: Component "' + id + '" not registered, and Loader not available');
            }
        });
    };

    ComponentFactory.prototype.get = function get(id) {
        return this._components.get(id);
    };

    ComponentFactory.prototype.register = function register(id, ctor) {
        this._components.set(id, ctor);
    };

    return ComponentFactory;
})();

exports.ComponentFactory = ComponentFactory;

var Link = (function () {
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
        var _this14 = this;

        var chan = this._channel;
        if (chan) {
            this._channel.endPoints.forEach(function (endPoint) {
                endPoint.detach(_this14._channel);
            });
            this._channel = undefined;
        }
        return chan;
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

exports.Link = Link;

var Network = (function (_EventHub2) {
    _inherits(Network, _EventHub2);

    function Network(factory, graph) {
        var _this15 = this;

        _classCallCheck(this, Network);

        _EventHub2.call(this);
        this._factory = factory;
        this._graph = graph || new Graph(null, {});
        var me = this;
        this._graph.subscribe(Graph.EVENT_ADD_NODE, function (data) {
            var runState = me._graph.context.runState;
            if (runState != RunState.NEWBORN) {
                (function () {
                    var node = data.node;

                    node.loadComponent(me._factory).then(function () {
                        if (Network.inState([RunState.RUNNING, RunState.PAUSED, RunState.READY], runState)) Network.setRunState(node, RunState.READY);
                        if (Network.inState([RunState.RUNNING, RunState.PAUSED], runState)) Network.setRunState(node, runState);
                        _this15.publish(Network.EVENT_GRAPH_CHANGE, { node: node });
                    });
                })();
            }
        });
    }

    Network.prototype.loadComponents = function loadComponents() {
        var _this16 = this;

        var me = this;
        this.publish(Network.EVENT_STATE_CHANGE, { state: RunState.LOADING });
        return this._graph.loadComponent(this._factory).then(function () {
            _this16.publish(Network.EVENT_STATE_CHANGE, { state: RunState.LOADED });
        });
    };

    Network.prototype.initialize = function initialize() {
        this.setRunState(RunState.READY);
    };

    Network.prototype.teardown = function teardown() {
        this.setRunState(RunState.LOADED);
    };

    Network.inState = function inState(states, runState) {
        return new Set(states).has(runState);
    };

    Network.setRunState = function setRunState(node, runState) {
        var ctx = node.context;
        var currentState = ctx.runState;
        if (node instanceof Graph) {
            var nodes = node.nodes;
            if (runState == RunState.LOADED && currentState >= RunState.READY) {
                var links = node.links;
                links.forEach(function (link) {
                    Network.unwireLink(link);
                });
            }
            nodes.forEach(function (subNode) {
                Network.setRunState(subNode, runState);
            });
            ctx.setRunState(runState);
            if (runState == RunState.READY && currentState >= RunState.LOADED) {
                var links = node.links;
                links.forEach(function (link) {
                    Network.wireLink(link);
                });
            }
        } else {
            ctx.setRunState(runState);
        }
    };

    Network.unwireLink = function unwireLink(link) {
        var fromNode = link.fromNode;
        var toNode = link.toNode;
        var chan = link.disconnect();
        if (chan) chan.deactivate();
    };

    Network.wireLink = function wireLink(link) {
        var fromNode = link.fromNode;
        var toNode = link.toNode;
        var channel = new Channel();
        link.connect(channel);
        channel.activate();
    };

    Network.prototype.setRunState = function setRunState(runState) {
        Network.setRunState(this._graph, runState);
        this.publish(Network.EVENT_STATE_CHANGE, { state: runState });
    };

    Network.prototype.start = function start() {
        var initiallyPaused = arguments.length <= 0 || arguments[0] === undefined ? false : arguments[0];

        this.setRunState(initiallyPaused ? RunState.PAUSED : RunState.RUNNING);
    };

    Network.prototype.step = function step() {};

    Network.prototype.stop = function stop() {
        this.setRunState(RunState.READY);
    };

    Network.prototype.pause = function pause() {
        this.setRunState(RunState.PAUSED);
    };

    Network.prototype.resume = function resume() {
        this.setRunState(RunState.RUNNING);
    };

    _createClass(Network, [{
        key: 'graph',
        get: function get() {
            return this._graph;
        }
    }]);

    return Network;
})(EventHub);

exports.Network = Network;

Network.EVENT_STATE_CHANGE = 'network:state-change';
Network.EVENT_GRAPH_CHANGE = 'network:graph-change';

var Graph = (function (_Node) {
    _inherits(Graph, _Node);

    function Graph(owner) {
        var attributes = arguments.length <= 1 || arguments[1] === undefined ? {} : arguments[1];

        _classCallCheck(this, Graph);

        _Node.call(this, owner, attributes);
        this.initFromObject(attributes);
    }

    Graph.prototype.initFromString = function initFromString(jsonString) {
        this.initFromObject(JSON.parse(jsonString));
    };

    Graph.prototype.initFromObject = function initFromObject(attributes) {
        var _this17 = this;

        this.id = attributes.id || "$graph";
        this._nodes = new Map();
        this._links = new Map();
        Object.keys(attributes.nodes || {}).forEach(function (id) {
            _this17.addNode(id, attributes.nodes[id]);
        });
        Object.keys(attributes.links || {}).forEach(function (id) {
            _this17.addLink(id, attributes.links[id]);
        });
    };

    Graph.prototype.toObject = function toObject(opts) {
        var graph = _Node.prototype.toObject.call(this);
        var nodes = graph["nodes"] = {};
        this._nodes.forEach(function (node, id) {
            nodes[id] = node.toObject();
        });
        var links = graph["links"] = {};
        this._links.forEach(function (link, id) {
            links[id] = link.toObject();
        });
        return graph;
    };

    Graph.prototype.loadComponent = function loadComponent(factory) {
        var _this18 = this;

        return new Promise(function (resolve, reject) {
            var pendingCount = 0;
            var nodes = new Map(_this18._nodes);
            nodes.set('$graph', _this18);
            nodes.forEach(function (node, id) {
                var done = undefined;
                pendingCount++;
                if (node == _this18) {
                    done = _Node.prototype.loadComponent.call(_this18, factory);
                } else {
                    done = node.loadComponent(factory);
                }
                done.then(function () {
                    --pendingCount;
                    if (pendingCount == 0) resolve();
                })['catch'](function (reason) {
                    reject(reason);
                });
            });
        });
    };

    Graph.prototype.getNodeByID = function getNodeByID(id) {
        if (id == '$graph') return this;
        return this._nodes.get(id);
    };

    Graph.prototype.addNode = function addNode(id, attributes) {
        var node = new Node(this, attributes);
        node.id = id;
        this._nodes.set(id, node);
        this.publish(Graph.EVENT_ADD_NODE, { node: node });
        return node;
    };

    Graph.prototype.renameNode = function renameNode(id, newID) {
        var node = this._nodes.get(id);
        if (id != newID) {
            var eventData = { node: node, attrs: { id: node.id } };
            this._nodes['delete'](id);
            node.id = newID;
            this._nodes.set(newID, node);
            this.publish(Graph.EVENT_UPD_NODE, eventData);
        }
    };

    Graph.prototype.removeNode = function removeNode(id) {
        var node = this._nodes.get(id);
        if (node) this.publish(Graph.EVENT_DEL_NODE, { node: node });
        return this._nodes['delete'](id);
    };

    Graph.prototype.getLinkByID = function getLinkByID(id) {
        return this._links[id];
    };

    Graph.prototype.addLink = function addLink(id, attributes) {
        var link = new Link(this, attributes);
        link.id = id;
        this._links.set(id, link);
        this.publish(Graph.EVENT_ADD_LINK, { link: link });
        return link;
    };

    Graph.prototype.renameLink = function renameLink(id, newID) {
        var link = this._links.get(id);
        this._links['delete'](id);
        var eventData = { link: link, attrs: { id: link.id } };
        link.id = newID;
        this.publish(Graph.EVENT_UPD_NODE, eventData);
        this._links.set(newID, link);
    };

    Graph.prototype.removeLink = function removeLink(id) {
        var link = this._links.get(id);
        if (link) this.publish(Graph.EVENT_DEL_LINK, { link: link });
        return this._links['delete'](id);
    };

    Graph.prototype.addPublicPort = function addPublicPort(id, attributes) {
        attributes["id"] = id;
        var port = new PublicPort(this, null, attributes);
        this._ports.set(id, port);
        return port;
    };

    _createClass(Graph, [{
        key: 'nodes',
        get: function get() {
            return this._nodes;
        }
    }, {
        key: 'links',
        get: function get() {
            return this._links;
        }
    }]);

    return Graph;
})(Node);

exports.Graph = Graph;

Graph.EVENT_ADD_NODE = 'graph:add-node';
Graph.EVENT_UPD_NODE = 'graph:upd-node';
Graph.EVENT_DEL_NODE = 'graph:del-node';
Graph.EVENT_ADD_LINK = 'graph:add-link';
Graph.EVENT_UPD_LINK = 'graph:upd-link';
Graph.EVENT_DEL_LINK = 'graph:del-link';

var SimulationEngine = (function () {
    function SimulationEngine(loader, container) {
        _classCallCheck(this, SimulationEngine);

        this.loader = loader;
        this.container = container;
    }

    SimulationEngine.prototype.getComponentFactory = function getComponentFactory() {
        return new ComponentFactory(this.container, this.loader);
    };

    return SimulationEngine;
})();

exports.SimulationEngine = SimulationEngine;