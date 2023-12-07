var Buffer = require('safe-buffer').Buffer;
var bcrypto = require('./crypto');
var bscript = require('./script');
var _a = require('./bufferutils'), BufferReader = _a.BufferReader, BufferWriter = _a.BufferWriter;
var _b = require('./forks/zcash/bufferutils'), ZcashBufferReader = _b.ZcashBufferReader, ZcashBufferWriter = _b.ZcashBufferWriter;
var coins = require('./coins');
var opcodes = require('bitcoin-ops');
var networks = require('./networks');
var typeforce = require('typeforce');
var types = require('./types');
var varuint = require('varuint-bitcoin');
var blake2b = require('@bitgo/blake2b');
var zcashVersion = require('./forks/zcash/version');
function varSliceSize(someScript) {
    var length = someScript.length;
    return varuint.encodingLength(length) + length;
}
function vectorSize(someVector) {
    var length = someVector.length;
    return varuint.encodingLength(length) + someVector.reduce(function (sum, witness) {
        return sum + varSliceSize(witness);
    }, 0);
}
// By default, assume is a bitcoin transaction
function Transaction(network) {
    if (network === void 0) { network = networks.bitcoin; }
    this.version = 1;
    this.locktime = 0;
    this.ins = [];
    this.outs = [];
    this.network = network;
    if (coins.isZcash(network)) {
        // ZCash version >= 2
        this.joinsplits = [];
        this.joinsplitPubkey = [];
        this.joinsplitSig = [];
        // ZCash version >= 3
        this.overwintered = 0; // 1 if the transaction is post overwinter upgrade, 0 otherwise
        this.versionGroupId = 0; // 0x03C48270 (63210096) for overwinter and 0x892F2085 (2301567109) for sapling
        this.expiryHeight = 0; // Block height after which this transactions will expire, or 0 to disable expiry
        // ZCash version >= 4
        this.valueBalance = 0;
        this.vShieldedSpend = [];
        this.vShieldedOutput = [];
        this.bindingSig = 0;
        // Must be updated along with version
        this.consensusBranchId = network.consensusBranchId[this.version];
    }
    if (coins.isDash(network)) {
        // Dash version = 3
        this.type = 0;
        this.extraPayload = Buffer.alloc(0);
    }
}
Transaction.DEFAULT_SEQUENCE = 0xffffffff;
Transaction.SIGHASH_ALL = 0x01;
Transaction.SIGHASH_NONE = 0x02;
Transaction.SIGHASH_SINGLE = 0x03;
Transaction.SIGHASH_ANYONECANPAY = 0x80;
Transaction.SIGHASH_BITCOINCASHBIP143 = 0x40;
Transaction.ADVANCED_TRANSACTION_MARKER = 0x00;
Transaction.ADVANCED_TRANSACTION_FLAG = 0x01;
var EMPTY_SCRIPT = Buffer.allocUnsafe(0);
var EMPTY_WITNESS = [];
var ZERO = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex');
var ONE = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
// Used to represent the absence of a value
var VALUE_UINT64_MAX = Buffer.from('ffffffffffffffff', 'hex');
var BLANK_OUTPUT = {
    script: EMPTY_SCRIPT,
    valueBuffer: VALUE_UINT64_MAX
};
Transaction.DASH_NORMAL = 0;
Transaction.DASH_PROVIDER_REGISTER = 1;
Transaction.DASH_PROVIDER_UPDATE_SERVICE = 2;
Transaction.DASH_PROVIDER_UPDATE_REGISTRAR = 3;
Transaction.DASH_PROVIDER_UPDATE_REVOKE = 4;
Transaction.DASH_COINBASE = 5;
Transaction.DASH_QUORUM_COMMITMENT = 6;
Transaction.fromBuffer = function (buffer, network, __noStrict) {
    if (network === void 0) { network = networks.bitcoin; }
    var bufferReader = new BufferReader(buffer);
    var tx = new Transaction(network);
    tx.version = bufferReader.readInt32();
    if (coins.isZcash(network)) {
        // Split the header into fOverwintered and nVersion
        tx.overwintered = tx.version >>> 31; // Must be 1 for version 3 and up
        tx.version = tx.version & 0x07FFFFFFF; // 3 for overwinter
        if (!network.consensusBranchId.hasOwnProperty(tx.version)) {
            throw new Error('Unsupported Zcash transaction');
        }
        tx.consensusBranchId = network.consensusBranchId[tx.version];
        bufferReader = new ZcashBufferReader(bufferReader.buffer, bufferReader.offset, tx.version);
    }
    if (coins.isDash(network)) {
        tx.type = tx.version >> 16;
        tx.version = tx.version & 0xffff;
        if (tx.version === 3 && (tx.type < Transaction.DASH_NORMAL || tx.type > Transaction.DASH_QUORUM_COMMITMENT)) {
            throw new Error('Unsupported Dash transaction type');
        }
    }
    var marker = bufferReader.readUInt8();
    var flag = bufferReader.readUInt8();
    var hasWitnesses = false;
    if (marker === Transaction.ADVANCED_TRANSACTION_MARKER &&
        flag === Transaction.ADVANCED_TRANSACTION_FLAG &&
        !coins.isZcash(network)) {
        hasWitnesses = true;
    }
    else {
        bufferReader.offset -= 2;
    }
    if (tx.isOverwinterCompatible()) {
        tx.versionGroupId = bufferReader.readUInt32();
    }
    var vinLen = bufferReader.readVarInt();
    for (var i = 0; i < vinLen; ++i) {
        tx.ins.push({
            hash: bufferReader.readSlice(32),
            index: bufferReader.readUInt32(),
            script: bufferReader.readVarSlice(),
            sequence: bufferReader.readUInt32(),
            witness: EMPTY_WITNESS
        });
    }
    var voutLen = bufferReader.readVarInt();
    for (i = 0; i < voutLen; ++i) {
        tx.outs.push({
            value: bufferReader.readUInt64(),
            script: bufferReader.readVarSlice()
        });
    }
    if (hasWitnesses) {
        for (i = 0; i < vinLen; ++i) {
            tx.ins[i].witness = bufferReader.readVector();
        }
        // was this pointless?
        if (!tx.hasWitnesses())
            throw new Error('Transaction has superfluous witness data');
    }
    tx.locktime = bufferReader.readUInt32();
    if (coins.isZcash(network)) {
        if (tx.isOverwinterCompatible()) {
            tx.expiryHeight = bufferReader.readUInt32();
        }
        if (tx.isSaplingCompatible()) {
            tx.valueBalance = bufferReader.readInt64();
            var nShieldedSpend = bufferReader.readVarInt();
            for (i = 0; i < nShieldedSpend; ++i) {
                tx.vShieldedSpend.push(bufferReader.readShieldedSpend());
            }
            var nShieldedOutput = bufferReader.readVarInt();
            for (i = 0; i < nShieldedOutput; ++i) {
                tx.vShieldedOutput.push(bufferReader.readShieldedOutput());
            }
        }
        if (tx.supportsJoinSplits()) {
            var joinSplitsLen = bufferReader.readVarInt();
            for (i = 0; i < joinSplitsLen; ++i) {
                tx.joinsplits.push(bufferReader.readJoinSplit());
            }
            if (joinSplitsLen > 0) {
                tx.joinsplitPubkey = bufferReader.readSlice(32);
                tx.joinsplitSig = bufferReader.readSlice(64);
            }
        }
        if (tx.isSaplingCompatible() &&
            tx.vShieldedSpend.length + tx.vShieldedOutput.length > 0) {
            tx.bindingSig = bufferReader.readSlice(64);
        }
    }
    if (tx.isDashSpecialTransaction()) {
        tx.extraPayload = bufferReader.readVarSlice();
    }
    tx.network = network;
    if (__noStrict)
        return tx;
    if (bufferReader.offset !== buffer.length)
        throw new Error('Transaction has unexpected data');
    return tx;
};
Transaction.fromHex = function (hex, network) {
    return Transaction.fromBuffer(Buffer.from(hex, 'hex'), network);
};
Transaction.isCoinbaseHash = function (buffer) {
    typeforce(types.Hash256bit, buffer);
    for (var i = 0; i < 32; ++i) {
        if (buffer[i] !== 0)
            return false;
    }
    return true;
};
Transaction.prototype.isSaplingCompatible = function () {
    return coins.isZcash(this.network) && this.version >= zcashVersion.SAPLING;
};
Transaction.prototype.isOverwinterCompatible = function () {
    return coins.isZcash(this.network) && this.version >= zcashVersion.OVERWINTER;
};
Transaction.prototype.supportsJoinSplits = function () {
    return coins.isZcash(this.network) && this.version >= zcashVersion.JOINSPLITS_SUPPORT;
};
Transaction.prototype.versionSupportsDashSpecialTransactions = function () {
    return coins.isDash(this.network) && this.version >= 3;
};
Transaction.prototype.isDashSpecialTransaction = function () {
    return this.versionSupportsDashSpecialTransactions() && this.type !== Transaction.DASH_NORMAL;
};
Transaction.prototype.isCoinbase = function () {
    return this.ins.length === 1 && Transaction.isCoinbaseHash(this.ins[0].hash);
};
Transaction.prototype.addInput = function (hash, index, sequence, scriptSig) {
    typeforce(types.tuple(types.Hash256bit, types.UInt32, types.maybe(types.UInt32), types.maybe(types.Buffer)), arguments);
    if (types.Null(sequence)) {
        sequence = Transaction.DEFAULT_SEQUENCE;
    }
    // Add the input and return the input's index
    return (this.ins.push({
        hash: hash,
        index: index,
        script: scriptSig || EMPTY_SCRIPT,
        sequence: sequence,
        witness: EMPTY_WITNESS
    }) - 1);
};
Transaction.prototype.addOutput = function (scriptPubKey, value) {
    typeforce(types.tuple(types.Buffer, types.Satoshi), arguments);
    // Add the output and return the output's index
    return (this.outs.push({
        script: scriptPubKey,
        value: value
    }) - 1);
};
Transaction.prototype.hasWitnesses = function () {
    return this.ins.some(function (x) {
        return x.witness.length !== 0;
    });
};
Transaction.prototype.weight = function () {
    var base = this.__byteLength(false);
    var total = this.__byteLength(true);
    return base * 3 + total;
};
Transaction.prototype.virtualSize = function () {
    return Math.ceil(this.weight() / 4);
};
Transaction.prototype.byteLength = function () {
    return this.__byteLength(true);
};
Transaction.prototype.getShieldedSpendByteLength = function () {
    if (!this.isSaplingCompatible()) {
        return 0;
    }
    var byteLength = 0;
    byteLength += varuint.encodingLength(this.vShieldedSpend.length); // nShieldedSpend
    byteLength += (384 * this.vShieldedSpend.length); // vShieldedSpend
    return byteLength;
};
Transaction.prototype.getShieldedOutputByteLength = function () {
    if (!this.isSaplingCompatible()) {
        return 0;
    }
    var byteLength = 0;
    byteLength += varuint.encodingLength(this.vShieldedOutput.length); // nShieldedOutput
    byteLength += (948 * this.vShieldedOutput.length); // vShieldedOutput
    return byteLength;
};
Transaction.prototype.getJoinSplitByteLength = function () {
    if (!this.supportsJoinSplits()) {
        return 0;
    }
    var joinSplitsLen = this.joinsplits.length;
    var byteLength = 0;
    byteLength += varuint.encodingLength(joinSplitsLen); // vJoinSplit
    if (joinSplitsLen > 0) {
        // Both pre and post Sapling JoinSplits are encoded with the following data:
        // 8 vpub_old, 8 vpub_new, 32 anchor, joinSplitsLen * 32 nullifiers, joinSplitsLen * 32 commitments, 32 ephemeralKey
        // 32 ephemeralKey, 32 randomSeed, joinsplit.macs.length * 32 vmacs
        if (this.isSaplingCompatible()) {
            byteLength += 1698 * joinSplitsLen; // vJoinSplit using JSDescriptionGroth16
        }
        else {
            byteLength += 1802 * joinSplitsLen; // vJoinSplit using JSDescriptionPHGR13
        }
        byteLength += 32; // joinSplitPubKey
        byteLength += 64; // joinSplitSig
    }
    return byteLength;
};
Transaction.prototype.zcashTransactionByteLength = function () {
    if (!coins.isZcash(this.network)) {
        throw new Error('zcashTransactionByteLength can only be called when using Zcash network');
    }
    var byteLength = 0;
    byteLength += 4; // Header
    if (this.isOverwinterCompatible()) {
        byteLength += 4; // nVersionGroupId
    }
    byteLength += varuint.encodingLength(this.ins.length); // tx_in_count
    byteLength += this.ins.reduce(function (sum, input) { return sum + 40 + varSliceSize(input.script); }, 0); // tx_in
    byteLength += varuint.encodingLength(this.outs.length); // tx_out_count
    byteLength += this.outs.reduce(function (sum, output) { return sum + 8 + varSliceSize(output.script); }, 0); // tx_out
    byteLength += 4; // lock_time
    if (this.isOverwinterCompatible()) {
        byteLength += 4; // nExpiryHeight
    }
    if (this.isSaplingCompatible()) {
        byteLength += 8; // valueBalance
        byteLength += this.getShieldedSpendByteLength();
        byteLength += this.getShieldedOutputByteLength();
    }
    if (this.supportsJoinSplits()) {
        byteLength += this.getJoinSplitByteLength();
    }
    if (this.isSaplingCompatible() &&
        this.vShieldedSpend.length + this.vShieldedOutput.length > 0) {
        byteLength += 64; // bindingSig
    }
    return byteLength;
};
Transaction.prototype.__byteLength = function (__allowWitness) {
    var hasWitnesses = __allowWitness && this.hasWitnesses();
    if (coins.isZcash(this.network)) {
        return this.zcashTransactionByteLength();
    }
    return ((hasWitnesses ? 10 : 8) +
        varuint.encodingLength(this.ins.length) +
        varuint.encodingLength(this.outs.length) +
        this.ins.reduce(function (sum, input) { return sum + 40 + varSliceSize(input.script); }, 0) +
        this.outs.reduce(function (sum, output) { return sum + 8 + varSliceSize(output.script); }, 0) +
        (this.isDashSpecialTransaction() ? varSliceSize(this.extraPayload) : 0) +
        (hasWitnesses ? this.ins.reduce(function (sum, input) { return sum + vectorSize(input.witness); }, 0) : 0));
};
Transaction.prototype.clone = function () {
    var newTx = new Transaction(this.network);
    newTx.version = this.version;
    newTx.locktime = this.locktime;
    newTx.network = this.network;
    if (coins.isDash(this.network)) {
        newTx.type = this.type;
        newTx.extraPayload = this.extraPayload;
    }
    if (coins.isZcash(this.network)) {
        newTx.consensusBranchId = this.consensusBranchId;
    }
    if (this.isOverwinterCompatible()) {
        newTx.overwintered = this.overwintered;
        newTx.versionGroupId = this.versionGroupId;
        newTx.expiryHeight = this.expiryHeight;
    }
    if (this.isSaplingCompatible()) {
        newTx.valueBalance = this.valueBalance;
    }
    newTx.ins = this.ins.map(function (txIn) {
        return {
            hash: txIn.hash,
            index: txIn.index,
            script: txIn.script,
            sequence: txIn.sequence,
            witness: txIn.witness
        };
    });
    newTx.outs = this.outs.map(function (txOut) {
        return {
            script: txOut.script,
            value: txOut.value
        };
    });
    if (this.isSaplingCompatible()) {
        newTx.vShieldedSpend = this.vShieldedSpend.map(function (shieldedSpend) {
            return {
                cv: shieldedSpend.cv,
                anchor: shieldedSpend.anchor,
                nullifier: shieldedSpend.nullifier,
                rk: shieldedSpend.rk,
                zkproof: shieldedSpend.zkproof,
                spendAuthSig: shieldedSpend.spendAuthSig
            };
        });
        newTx.vShieldedOutput = this.vShieldedOutput.map(function (shieldedOutput) {
            return {
                cv: shieldedOutput.cv,
                cmu: shieldedOutput.cmu,
                ephemeralKey: shieldedOutput.ephemeralKey,
                encCiphertext: shieldedOutput.encCiphertext,
                outCiphertext: shieldedOutput.outCiphertext,
                zkproof: shieldedOutput.zkproof
            };
        });
    }
    if (this.supportsJoinSplits()) {
        newTx.joinsplits = this.joinsplits.map(function (txJoinsplit) {
            return {
                vpubOld: txJoinsplit.vpubOld,
                vpubNew: txJoinsplit.vpubNew,
                anchor: txJoinsplit.anchor,
                nullifiers: txJoinsplit.nullifiers,
                commitments: txJoinsplit.commitments,
                ephemeralKey: txJoinsplit.ephemeralKey,
                randomSeed: txJoinsplit.randomSeed,
                macs: txJoinsplit.macs,
                zkproof: txJoinsplit.zkproof,
                ciphertexts: txJoinsplit.ciphertexts
            };
        });
        newTx.joinsplitPubkey = this.joinsplitPubkey;
        newTx.joinsplitSig = this.joinsplitSig;
    }
    if (this.isSaplingCompatible() && this.vShieldedSpend.length + this.vShieldedOutput.length > 0) {
        newTx.bindingSig = this.bindingSig;
    }
    return newTx;
};
/**
 * Get Zcash header or version
 * @returns {number}
 */
Transaction.prototype.getHeader = function () {
    var mask = (this.overwintered ? 1 : 0);
    var header = this.version | (mask << 31);
    return header;
};
/**
 * Hash transaction for signing a specific input.
 *
 * Bitcoin uses a different hash for each signed transaction input.
 * This method copies the transaction, makes the necessary changes based on the
 * hashType, and then hashes the result.
 * This hash can then be used to sign the provided transaction input.
 */
Transaction.prototype.hashForSignature = function (inIndex, prevOutScript, hashType) {
    typeforce(types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number), arguments);
    // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
    if (inIndex >= this.ins.length)
        return ONE;
    // ignore OP_CODESEPARATOR
    var ourScript = bscript.compile(bscript.decompile(prevOutScript).filter(function (x) {
        return x !== opcodes.OP_CODESEPARATOR;
    }));
    var txTmp = this.clone();
    // SIGHASH_NONE: ignore all outputs? (wildcard payee)
    if ((hashType & 0x1f) === Transaction.SIGHASH_NONE) {
        txTmp.outs = [];
        // ignore sequence numbers (except at inIndex)
        txTmp.ins.forEach(function (input, i) {
            if (i === inIndex)
                return;
            input.sequence = 0;
        });
        // SIGHASH_SINGLE: ignore all outputs, except at the same index?
    }
    else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE) {
        // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L60
        if (inIndex >= this.outs.length)
            return ONE;
        // truncate outputs after
        txTmp.outs.length = inIndex + 1;
        // "blank" outputs before
        for (var i = 0; i < inIndex; i++) {
            txTmp.outs[i] = BLANK_OUTPUT;
        }
        // ignore sequence numbers (except at inIndex)
        txTmp.ins.forEach(function (input, y) {
            if (y === inIndex)
                return;
            input.sequence = 0;
        });
    }
    // SIGHASH_ANYONECANPAY: ignore inputs entirely?
    if (hashType & Transaction.SIGHASH_ANYONECANPAY) {
        txTmp.ins = [txTmp.ins[inIndex]];
        txTmp.ins[0].script = ourScript;
        // SIGHASH_ALL: only ignore input scripts
    }
    else {
        // "blank" others input scripts
        txTmp.ins.forEach(function (input) { input.script = EMPTY_SCRIPT; });
        txTmp.ins[inIndex].script = ourScript;
    }
    // serialize and hash
    var buffer = Buffer.allocUnsafe(txTmp.__byteLength(false) + 4);
    buffer.writeInt32LE(hashType, buffer.length - 4);
    txTmp.__toBuffer(buffer, 0, false);
    return bcrypto.hash256(buffer);
};
/**
 * Blake2b hashing algorithm for Zcash
 * @param bufferToHash
 * @param personalization
 * @returns 256-bit BLAKE2b hash
 */
Transaction.prototype.getBlake2bHash = function (bufferToHash, personalization) {
    var out = Buffer.allocUnsafe(32);
    return blake2b(out.length, null, null, Buffer.from(personalization)).update(bufferToHash).digest(out);
};
/**
 * Build a hash for all or none of the transaction inputs depending on the hashtype
 * @param hashType
 * @returns double SHA-256, 256-bit BLAKE2b hash or 256-bit zero if doesn't apply
 */
Transaction.prototype.getPrevoutHash = function (hashType) {
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
        var bufferWriter = new BufferWriter(Buffer.allocUnsafe(36 * this.ins.length));
        this.ins.forEach(function (txIn) {
            bufferWriter.writeSlice(txIn.hash);
            bufferWriter.writeUInt32(txIn.index);
        });
        if (coins.isZcash(this.network)) {
            return this.getBlake2bHash(bufferWriter.buffer, 'ZcashPrevoutHash');
        }
        return bcrypto.hash256(bufferWriter.buffer);
    }
    return ZERO;
};
/**
 * Build a hash for all or none of the transactions inputs sequence numbers depending on the hashtype
 * @param hashType
 * @returns double SHA-256, 256-bit BLAKE2b hash or 256-bit zero if doesn't apply
 */
Transaction.prototype.getSequenceHash = function (hashType) {
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY) &&
        (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
        (hashType & 0x1f) !== Transaction.SIGHASH_NONE) {
        var bufferWriter = new BufferWriter(Buffer.allocUnsafe(4 * this.ins.length));
        this.ins.forEach(function (txIn) {
            bufferWriter.writeUInt32(txIn.sequence);
        });
        if (coins.isZcash(this.network)) {
            return this.getBlake2bHash(bufferWriter.buffer, 'ZcashSequencHash');
        }
        return bcrypto.hash256(bufferWriter.buffer);
    }
    return ZERO;
};
/**
 * Build a hash for one, all or none of the transaction outputs depending on the hashtype
 * @param hashType
 * @param inIndex
 * @returns double SHA-256, 256-bit BLAKE2b hash or 256-bit zero if doesn't apply
 */
Transaction.prototype.getOutputsHash = function (hashType, inIndex) {
    var bufferWriter;
    if ((hashType & 0x1f) !== Transaction.SIGHASH_SINGLE && (hashType & 0x1f) !== Transaction.SIGHASH_NONE) {
        // Find out the size of the outputs and write them
        var txOutsSize = this.outs.reduce(function (sum, output) {
            return sum + 8 + varSliceSize(output.script);
        }, 0);
        bufferWriter = new BufferWriter(Buffer.allocUnsafe(txOutsSize));
        this.outs.forEach(function (out) {
            bufferWriter.writeUInt64(out.value);
            bufferWriter.writeVarSlice(out.script);
        });
        if (coins.isZcash(this.network)) {
            return this.getBlake2bHash(bufferWriter.buffer, 'ZcashOutputsHash');
        }
        return bcrypto.hash256(bufferWriter.buffer);
    }
    else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE && inIndex < this.outs.length) {
        // Write only the output specified in inIndex
        var output = this.outs[inIndex];
        bufferWriter = new BufferWriter(Buffer.allocUnsafe(8 + varSliceSize(output.script)));
        bufferWriter.writeUInt64(output.value);
        bufferWriter.writeVarSlice(output.script);
        if (coins.isZcash(this.network)) {
            return this.getBlake2bHash(bufferWriter.buffer, 'ZcashOutputsHash');
        }
        return bcrypto.hash256(bufferWriter.buffer);
    }
    return ZERO;
};
/**
 * Hash transaction for signing a transparent transaction in Zcash. Protected transactions are not supported.
 * @param inIndex
 * @param prevOutScript
 * @param value
 * @param hashType
 * @returns double SHA-256 or 256-bit BLAKE2b hash
 */
Transaction.prototype.hashForZcashSignature = function (inIndex, prevOutScript, value, hashType) {
    typeforce(types.tuple(types.UInt32, types.Buffer, types.Satoshi, types.UInt32), arguments);
    if (!coins.isZcash(this.network)) {
        throw new Error('hashForZcashSignature can only be called when using Zcash network');
    }
    if (this.joinsplits.length > 0) {
        throw new Error('Hash signature for Zcash protected transactions is not supported');
    }
    if (inIndex >= this.ins.length && inIndex !== VALUE_UINT64_MAX) {
        throw new Error('Input index is out of range');
    }
    if (this.isOverwinterCompatible()) {
        var hashPrevouts = this.getPrevoutHash(hashType);
        var hashSequence = this.getSequenceHash(hashType);
        var hashOutputs = this.getOutputsHash(hashType, inIndex);
        var hashJoinSplits = ZERO;
        var hashShieldedSpends = ZERO;
        var hashShieldedOutputs = ZERO;
        var bufferWriter;
        var baseBufferSize = 0;
        baseBufferSize += 4 * 5; // header, nVersionGroupId, lock_time, nExpiryHeight, hashType
        baseBufferSize += 32 * 4; // 256 hashes: hashPrevouts, hashSequence, hashOutputs, hashJoinSplits
        if (inIndex !== VALUE_UINT64_MAX) {
            // If this hash is for a transparent input signature (i.e. not for txTo.joinSplitSig), we need extra space
            baseBufferSize += 4 * 2; // input.index, input.sequence
            baseBufferSize += 8; // value
            baseBufferSize += 32; // input.hash
            baseBufferSize += varSliceSize(prevOutScript); // prevOutScript
        }
        if (this.isSaplingCompatible()) {
            baseBufferSize += 32 * 2; // hashShieldedSpends and hashShieldedOutputs
            baseBufferSize += 8; // valueBalance
        }
        bufferWriter = new BufferWriter(Buffer.alloc(baseBufferSize));
        bufferWriter.writeInt32(this.getHeader());
        bufferWriter.writeUInt32(this.versionGroupId);
        bufferWriter.writeSlice(hashPrevouts);
        bufferWriter.writeSlice(hashSequence);
        bufferWriter.writeSlice(hashOutputs);
        bufferWriter.writeSlice(hashJoinSplits);
        if (this.isSaplingCompatible()) {
            bufferWriter.writeSlice(hashShieldedSpends);
            bufferWriter.writeSlice(hashShieldedOutputs);
        }
        bufferWriter.writeUInt32(this.locktime);
        bufferWriter.writeUInt32(this.expiryHeight);
        if (this.isSaplingCompatible()) {
            bufferWriter.writeUInt64(this.valueBalance);
        }
        bufferWriter.writeUInt32(hashType);
        // If this hash is for a transparent input signature (i.e. not for txTo.joinSplitSig):
        if (inIndex !== VALUE_UINT64_MAX) {
            // The input being signed (replacing the scriptSig with scriptCode + amount)
            // The prevout may already be contained in hashPrevout, and the nSequence
            // may already be contained in hashSequence.
            var input = this.ins[inIndex];
            bufferWriter.writeSlice(input.hash);
            bufferWriter.writeUInt32(input.index);
            bufferWriter.writeVarSlice(prevOutScript);
            bufferWriter.writeUInt64(value);
            bufferWriter.writeUInt32(input.sequence);
        }
        var personalization = Buffer.alloc(16);
        var prefix = 'ZcashSigHash';
        personalization.write(prefix);
        personalization.writeUInt32LE(this.consensusBranchId, prefix.length);
        return this.getBlake2bHash(bufferWriter.buffer, personalization);
    }
    // TODO: support non overwinter transactions
};
Transaction.prototype.hashForWitnessV0 = function (inIndex, prevOutScript, value, hashType) {
    typeforce(types.tuple(types.UInt32, types.Buffer, types.Satoshi, types.UInt32), arguments);
    var hashPrevouts = this.getPrevoutHash(hashType);
    var hashSequence = this.getSequenceHash(hashType);
    var hashOutputs = this.getOutputsHash(hashType, inIndex);
    var bufferWriter = new BufferWriter(Buffer.allocUnsafe(156 + varSliceSize(prevOutScript)));
    var input = this.ins[inIndex];
    bufferWriter.writeUInt32(this.version);
    bufferWriter.writeSlice(hashPrevouts);
    bufferWriter.writeSlice(hashSequence);
    bufferWriter.writeSlice(input.hash);
    bufferWriter.writeUInt32(input.index);
    bufferWriter.writeVarSlice(prevOutScript);
    bufferWriter.writeUInt64(value);
    bufferWriter.writeUInt32(input.sequence);
    bufferWriter.writeSlice(hashOutputs);
    bufferWriter.writeUInt32(this.locktime);
    bufferWriter.writeUInt32(hashType);
    return bcrypto.hash256(bufferWriter.buffer);
};
/**
 * Hash transaction for signing a specific input for Bitcoin Cash.
 */
Transaction.prototype.hashForCashSignature = function (inIndex, prevOutScript, inAmount, hashType) {
    typeforce(types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number, types.maybe(types.UInt53)), arguments);
    // This function works the way it does because Bitcoin Cash
    // uses BIP143 as their replay protection, AND their algo
    // includes `forkId | hashType`, AND since their forkId=0,
    // this is a NOP, and has no difference to segwit. To support
    // other forks, another parameter is required, and a new parameter
    // would be required in the hashForWitnessV0 function, or
    // it could be broken into two..
    // BIP143 sighash activated in BitcoinCash via 0x40 bit
    if (hashType & Transaction.SIGHASH_BITCOINCASHBIP143) {
        if (types.Null(inAmount)) {
            throw new Error('Bitcoin Cash sighash requires value of input to be signed.');
        }
        return this.hashForWitnessV0(inIndex, prevOutScript, inAmount, hashType);
    }
    else {
        return this.hashForSignature(inIndex, prevOutScript, hashType);
    }
};
/**
 * Hash transaction for signing a specific input for Bitcoin Gold.
 */
Transaction.prototype.hashForGoldSignature = function (inIndex, prevOutScript, inAmount, hashType, sigVersion) {
    typeforce(types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number, types.maybe(types.UInt53)), arguments);
    // Bitcoin Gold also implements segregated witness
    // therefore we can pull out the setting of nForkHashType
    // and pass it into the functions.
    var nForkHashType = hashType;
    var fUseForkId = (hashType & Transaction.SIGHASH_BITCOINCASHBIP143) > 0;
    if (fUseForkId) {
        nForkHashType |= this.network.forkId << 8;
    }
    // BIP143 sighash activated in BitcoinCash via 0x40 bit
    if (sigVersion || fUseForkId) {
        if (types.Null(inAmount)) {
            throw new Error('Bitcoin Cash sighash requires value of input to be signed.');
        }
        return this.hashForWitnessV0(inIndex, prevOutScript, inAmount, nForkHashType);
    }
    else {
        return this.hashForSignature(inIndex, prevOutScript, nForkHashType);
    }
};
Transaction.prototype.getHash = function () {
    return bcrypto.hash256(this.__toBuffer(undefined, undefined, false));
};
Transaction.prototype.getId = function () {
    // transaction hash's are displayed in reverse order
    return this.getHash().reverse().toString('hex');
};
Transaction.prototype.toBuffer = function (buffer, initialOffset) {
    return this.__toBuffer(buffer, initialOffset, true);
};
Transaction.prototype.__toBuffer = function (buffer, initialOffset, __allowWitness) {
    if (!buffer)
        buffer = Buffer.allocUnsafe(this.__byteLength(__allowWitness));
    var bufferWriter = coins.isZcash(this.network)
        ? new ZcashBufferWriter(buffer, initialOffset || 0)
        : new BufferWriter(buffer, initialOffset || 0);
    function writeUInt16(i) {
        bufferWriter.offset = bufferWriter.buffer.writeUInt16LE(i, bufferWriter.offset);
    }
    if (this.isOverwinterCompatible()) {
        var mask = (this.overwintered ? 1 : 0);
        bufferWriter.writeInt32(this.version | (mask << 31)); // Set overwinter bit
        bufferWriter.writeUInt32(this.versionGroupId);
    }
    else if (this.isDashSpecialTransaction()) {
        writeUInt16(this.version);
        writeUInt16(this.type);
    }
    else {
        bufferWriter.writeInt32(this.version);
    }
    var hasWitnesses = __allowWitness && this.hasWitnesses();
    if (hasWitnesses) {
        bufferWriter.writeUInt8(Transaction.ADVANCED_TRANSACTION_MARKER);
        bufferWriter.writeUInt8(Transaction.ADVANCED_TRANSACTION_FLAG);
    }
    bufferWriter.writeVarInt(this.ins.length);
    this.ins.forEach(function (txIn) {
        bufferWriter.writeSlice(txIn.hash);
        bufferWriter.writeUInt32(txIn.index);
        bufferWriter.writeVarSlice(txIn.script);
        bufferWriter.writeUInt32(txIn.sequence);
    });
    bufferWriter.writeVarInt(this.outs.length);
    this.outs.forEach(function (txOut) {
        if (!txOut.valueBuffer) {
            bufferWriter.writeUInt64(txOut.value);
        }
        else {
            bufferWriter.writeSlice(txOut.valueBuffer);
        }
        bufferWriter.writeVarSlice(txOut.script);
    });
    if (hasWitnesses) {
        this.ins.forEach(function (input) {
            bufferWriter.writeVector(input.witness);
        });
    }
    bufferWriter.writeUInt32(this.locktime);
    if (this.isOverwinterCompatible()) {
        bufferWriter.writeUInt32(this.expiryHeight);
    }
    if (this.isSaplingCompatible()) {
        bufferWriter.writeUInt64(this.valueBalance);
        bufferWriter.writeVarInt(this.vShieldedSpend.length);
        this.vShieldedSpend.forEach(function (shieldedSpend) {
            bufferWriter.writeSlice(shieldedSpend.cv);
            bufferWriter.writeSlice(shieldedSpend.anchor);
            bufferWriter.writeSlice(shieldedSpend.nullifier);
            bufferWriter.writeSlice(shieldedSpend.rk);
            bufferWriter.writeSlice(shieldedSpend.zkproof.sA);
            bufferWriter.writeSlice(shieldedSpend.zkproof.sB);
            bufferWriter.writeSlice(shieldedSpend.zkproof.sC);
            bufferWriter.writeSlice(shieldedSpend.spendAuthSig);
        });
        bufferWriter.writeVarInt(this.vShieldedOutput.length);
        this.vShieldedOutput.forEach(function (shieldedOutput) {
            bufferWriter.writeSlice(shieldedOutput.cv);
            bufferWriter.writeSlice(shieldedOutput.cmu);
            bufferWriter.writeSlice(shieldedOutput.ephemeralKey);
            bufferWriter.writeSlice(shieldedOutput.encCiphertext);
            bufferWriter.writeSlice(shieldedOutput.outCiphertext);
            bufferWriter.writeSlice(shieldedOutput.zkproof.sA);
            bufferWriter.writeSlice(shieldedOutput.zkproof.sB);
            bufferWriter.writeSlice(shieldedOutput.zkproof.sC);
        });
    }
    if (this.supportsJoinSplits()) {
        bufferWriter.writeVarInt(this.joinsplits.length);
        this.joinsplits.forEach(function (joinsplit) {
            bufferWriter.writeUInt64(joinsplit.vpubOld);
            bufferWriter.writeUInt64(joinsplit.vpubNew);
            bufferWriter.writeSlice(joinsplit.anchor);
            joinsplit.nullifiers.forEach(function (nullifier) {
                bufferWriter.writeSlice(nullifier);
            });
            joinsplit.commitments.forEach(function (nullifier) {
                bufferWriter.writeSlice(nullifier);
            });
            bufferWriter.writeSlice(joinsplit.ephemeralKey);
            bufferWriter.writeSlice(joinsplit.randomSeed);
            joinsplit.macs.forEach(function (nullifier) {
                bufferWriter.writeSlice(nullifier);
            });
            if (this.isSaplingCompatible()) {
                bufferWriter.writeSlice(joinsplit.zkproof.sA);
                bufferWriter.writeSlice(joinsplit.zkproof.sB);
                bufferWriter.writeSlice(joinsplit.zkproof.sC);
            }
            else {
                bufferWriter.writeCompressedG1(joinsplit.zkproof.gA);
                bufferWriter.writeCompressedG1(joinsplit.zkproof.gAPrime);
                bufferWriter.writeCompressedG2(joinsplit.zkproof.gB);
                bufferWriter.writeCompressedG1(joinsplit.zkproof.gBPrime);
                bufferWriter.writeCompressedG1(joinsplit.zkproof.gC);
                bufferWriter.writeCompressedG1(joinsplit.zkproof.gCPrime);
                bufferWriter.writeCompressedG1(joinsplit.zkproof.gK);
                bufferWriter.writeCompressedG1(joinsplit.zkproof.gH);
            }
            joinsplit.ciphertexts.forEach(function (ciphertext) {
                bufferWriter.writeSlice(ciphertext);
            });
        }, this);
        if (this.joinsplits.length > 0) {
            bufferWriter.writeSlice(this.joinsplitPubkey);
            bufferWriter.writeSlice(this.joinsplitSig);
        }
    }
    if (this.isSaplingCompatible() && this.vShieldedSpend.length + this.vShieldedOutput.length > 0) {
        bufferWriter.writeSlice(this.bindingSig);
    }
    if (this.isDashSpecialTransaction()) {
        bufferWriter.writeVarSlice(this.extraPayload);
    }
    if (initialOffset !== undefined)
        return buffer.slice(initialOffset, bufferWriter.offset);
    // avoid slicing unless necessary
    // TODO (https://github.com/BitGo/bitgo-utxo-lib/issues/11): we shouldn't have to slice the final buffer
    return buffer.slice(0, bufferWriter.offset);
};
Transaction.prototype.toHex = function () {
    return this.toBuffer().toString('hex');
};
Transaction.prototype.setInputScript = function (index, scriptSig) {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);
    this.ins[index].script = scriptSig;
};
Transaction.prototype.setWitness = function (index, witness) {
    typeforce(types.tuple(types.Number, [types.Buffer]), arguments);
    this.ins[index].witness = witness;
};
module.exports = Transaction;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidHJhbnNhY3Rpb24uanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvdHJhbnNhY3Rpb24uanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsSUFBSSxNQUFNLEdBQUcsT0FBTyxDQUFDLGFBQWEsQ0FBQyxDQUFDLE1BQU0sQ0FBQTtBQUMxQyxJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUE7QUFDakMsSUFBSSxPQUFPLEdBQUcsT0FBTyxDQUFDLFVBQVUsQ0FBQyxDQUFBO0FBQzdCLElBQUEsS0FBaUMsT0FBTyxDQUFDLGVBQWUsQ0FBQyxFQUF2RCxZQUFZLGtCQUFBLEVBQUUsWUFBWSxrQkFBNkIsQ0FBQTtBQUN6RCxJQUFBLEtBQTJDLE9BQU8sQ0FBQywyQkFBMkIsQ0FBQyxFQUE3RSxpQkFBaUIsdUJBQUEsRUFBRSxpQkFBaUIsdUJBQXlDLENBQUE7QUFDbkYsSUFBSSxLQUFLLEdBQUcsT0FBTyxDQUFDLFNBQVMsQ0FBQyxDQUFBO0FBQzlCLElBQUksT0FBTyxHQUFHLE9BQU8sQ0FBQyxhQUFhLENBQUMsQ0FBQTtBQUNwQyxJQUFJLFFBQVEsR0FBRyxPQUFPLENBQUMsWUFBWSxDQUFDLENBQUE7QUFDcEMsSUFBSSxTQUFTLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFBO0FBQ3BDLElBQUksS0FBSyxHQUFHLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQTtBQUM5QixJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsaUJBQWlCLENBQUMsQ0FBQTtBQUN4QyxJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsZ0JBQWdCLENBQUMsQ0FBQTtBQUV2QyxJQUFJLFlBQVksR0FBRyxPQUFPLENBQUMsdUJBQXVCLENBQUMsQ0FBQTtBQUVuRCxTQUFTLFlBQVksQ0FBRSxVQUFVO0lBQy9CLElBQUksTUFBTSxHQUFHLFVBQVUsQ0FBQyxNQUFNLENBQUE7SUFFOUIsT0FBTyxPQUFPLENBQUMsY0FBYyxDQUFDLE1BQU0sQ0FB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QUF3RztJQUN4RyxPQUFPLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLFlBQVksQ0FBQyxNQUFNLENBQUMsQ0FBQTtBQUM3QyxDQUFDLENBQUE7QUFFRCxXQUFXLENBQUMsU0FBUyxDQUFDLEtBQUssR0FBRztJQUM1QixPQUFPLElBQUksQ0FBQyxRQUFRLEVBQUUsQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLENBQUE7QUFDeEMsQ0FBQyxDQUFBO0FBRUQsV0FBVyxDQUFDLFNBQVMsQ0FBQyxjQUFjLEdBQUcsVUFBVSxLQUFLLEVBQUUsU0FBUztJQUMvRCxTQUFTLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsTUFBTSxFQUFFLEtBQUssQ0FBQyxNQUFNLENBQUMsRUFBRSxTQUFTLENBQUMsQ0FBQTtJQUU3RCxJQUFJLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLE1BQU0sR0FBRyxTQUFTLENBQUE7QUFDcEMsQ0FBQyxDQUFBO0FBRUQsV0FBVyxDQUFDLFNBQVMsQ0FBQyxVQUFVLEdBQUcsVUFBVSxLQUFLLEVBQUUsT0FBTztJQUN6RCxTQUFTLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsTUFBTSxFQUFFLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEVBQUUsU0FBUyxDQUFDLENBQUE7SUFFL0QsSUFBSSxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxPQUFPLEdBQUcsT0FBTyxDQUFBO0FBQ25DLENBQUMsQ0FBQTtBQUVELE1BQU0sQ0FBQyxPQUFPLEdBQUcsV0FBVyxDQUFBIiwic291cmNlc0NvbnRlbnQiOlsidmFyIEJ1ZmZlciA9IHJlcXVpcmUoJ3NhZmUtYnVmZmVyJykuQnVmZmVyXG52YXIgYmNyeXB0byA9IHJlcXVpcmUoJy4vY3J5cHRvJylcbnZhciBic2NyaXB0ID0gcmVxdWlyZSgnLi9zY3JpcHQnKVxudmFyIHsgQnVmZmVyUmVhZGVyLCBCdWZmZXJXcml0ZXIgfSA9IHJlcXVpcmUoJy4vYnVmZmVydXRpbHMnKVxudmFyIHsgWmNhc2hCdWZmZXJSZWFkZXIsIFpjYXNoQnVmZmVyV3JpdGVyIH0gPSByZXF1aXJlKCcuL2ZvcmtzL3pjYXNoL2J1ZmZlcnV0aWxzJylcbnZhciBjb2lucyA9IHJlcXVpcmUoJy4vY29pbnMnKVxudmFyIG9wY29kZXMgPSByZXF1aXJlKCdiaXRjb2luLW9wcycpXG52YXIgbmV0d29ya3MgPSByZXF1aXJlKCcuL25ldHdvcmtzJylcbnZhciB0eXBlZm9yY2UgPSByZXF1aXJlKCd0eXBlZm9yY2UnKVxudmFyIHR5cGVzID0gcmVxdWlyZSgnLi90eXBlcycpXG52YXIgdmFydWludCA9IHJlcXVpcmUoJ3ZhcnVpbnQtYml0Y29pbicpXG52YXIgYmxha2UyYiA9IHJlcXVpcmUoJ0BiaXRnby9ibGFrZTJiJylcblxudmFyIHpjYXNoVmVyc2lvbiA9IHJlcXVpcmUoJy4vZm9ya3MvemNhc2gvdmVyc2lvbicpXG5cbmZ1bmN0aW9uIHZhclNsaWNlU2l6ZSAoc29tZVNjcmlwdCkge1xuICB2YXIgbGVuZ3RoID0gc29tZVNjcmlwdC5sZW5ndGhcblxuICByZXR1cm4gdmFydWludC5lbmNvZGluZ0xlbmd0aChsZW5ndGgpICsgbGVuZ3RoXG59XG5cbmZ1bmN0aW9uIHZlY3RvclNpemUgKHNvbWVWZWN0b3IpIHtcbiAgdmFyIGxlbmd0aCA9IHNvbWVWZWN0b3IubGVuZ3RoXG5cbiAgcmV0dXJuIHZhcnVpbnQuZW5jb2RpbmdMZW5ndGgobGVuZ3RoKSArIHNvbWVWZWN0b3IucmVkdWNlKGZ1bmN0aW9uIChzdW0sIHdpdG5lc3MpIHtcbiAgICByZXR1cm4gc3VtICsgdmFyU2xpY2VTaXplKHdpdG5lc3MpXG4gIH0sIDApXG59XG5cbi8vIEJ5IGRlZmF1bHQsIGFzc3VtZSBpcyBhIGJpdGNvaW4gdHJhbnNhY3Rpb25cbmZ1bmN0aW9uIFRyYW5zYWN0aW9uIChuZXR3b3JrID0gbmV0d29ya3MuYml0Y29pbikge1xuICB0aGlzLnZlcnNpb24gPSAxXG4gIHRoaXMubG9ja3RpbWUgPSAwXG4gIHRoaXMuaW5zID0gW11cbiAgdGhpcy5vdXRzID0gW11cbiAgdGhpcy5uZXR3b3JrID0gbmV0d29ya1xuICBpZiAoY29pbnMuaXNaY2FzaChuZXR3b3JrKSkge1xuICAgIC8vIFpDYXNoIHZlcnNpb24gPj0gMlxuICAgIHRoaXMuam9pbnNwbGl0cyA9IFtdXG4gICAgdGhpcy5qb2luc3BsaXRQdWJrZXkgPSBbXVxuICAgIHRoaXMuam9pbnNwbGl0U2lnID0gW11cbiAgICAvLyBaQ2FzaCB2ZXJzaW9uID49IDNcbiAgICB0aGlzLm92ZXJ3aW50ZXJlZCA9IDAgIC8vIDEgaWYgdGhlIHRyYW5zYWN0aW9uIGlzIHBvc3Qgb3ZlcndpbnRlciB1cGdyYWRlLCAwIG90aGVyd2lzZVxuICAgIHRoaXMudmVyc2lvbkdyb3VwSWQgPSAwICAvLyAweDAzQzQ4MjcwICg2MzIxMDA5NikgZm9yIG92ZXJ3aW50ZXIgYW5kIDB4ODkyRjIwODUgKDIzMDE1NjcxMDkpIGZvciBzYXBsaW5nXG4gICAgdGhpcy5leHBpcnlIZWlnaHQgPSAwICAvLyBCbG9jayBoZWlnaHQgYWZ0ZXIgd2hpY2ggdGhpcyB0cmFuc2FjdGlvbnMgd2lsbCBleHBpcmUsIG9yIDAgdG8gZGlzYWJsZSBleHBpcnlcbiAgICAvLyBaQ2FzaCB2ZXJzaW9uID49IDRcbiAgICB0aGlzLnZhbHVlQmFsYW5jZSA9IDBcbiAgICB0aGlzLnZTaGllbGRlZFNwZW5kID0gW11cbiAgICB0aGlzLnZTaGllbGRlZE91dHB1dCA9IFtdXG4gICAgdGhpcy5iaW5kaW5nU2lnID0gMFxuICAgIC8vIE11c3QgYmUgdXBkYXRlZCBhbG9uZyB3aXRoIHZlcnNpb25cbiAgICB0aGlzLmNvbnNlbnN1c0JyYW5jaElkID0gbmV0d29yay5jb25zZW5zdXNCcmFuY2hJZFt0aGlzLnZlcnNpb25dXG4gIH1cbiAgaWYgKGNvaW5zLmlzRGFzaChuZXR3b3JrKSkge1xuICAgIC8vIERhc2ggdmVyc2lvbiA9IDNcbiAgICB0aGlzLnR5cGUgPSAwXG4gICAgdGhpcy5leHRyYVBheWxvYWQgPSBCdWZmZXIuYWxsb2MoMClcbiAgfVxufVxuXG5UcmFuc2FjdGlvbi5ERUZBVUxUX1NFUVVFTkNFID0gMHhmZmZmZmZmZlxuVHJhbnNhY3Rpb24uU0lHSEFTSF9BTEwgPSAweDAxXG5UcmFuc2FjdGlvbi5TSUdIQVNIX05PTkUgPSAweDAyXG5UcmFuc2FjdGlvbi5TSUdIQVNIX1NJTkdMRSA9IDB4MDNcblRyYW5zYWN0aW9uLlNJR0hBU0hfQU5ZT05FQ0FOUEFZID0gMHg4MFxuVHJhbnNhY3Rpb24uU0lHSEFTSF9CSVRDT0lOQ0FTSEJJUDE0MyA9IDB4NDBcblRyYW5zYWN0aW9uLkFEVkFOQ0VEX1RSQU5TQUNUSU9OX01BUktFUiA9IDB4MDBcblRyYW5zYWN0aW9uLkFEVkFOQ0VEX1RSQU5TQUNUSU9OX0ZMQUcgPSAweDAxXG5cbnZhciBFTVBUWV9TQ1JJUFQgPSBCdWZmZXIuYWxsb2NVbnNhZmUoMClcbnZhciBFTVBUWV9XSVRORVNTID0gW11cbnZhciBaRVJPID0gQnVmZmVyLmZyb20oJzAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAnLCAnaGV4JylcbnZhciBPTkUgPSBCdWZmZXIuZnJvbSgnMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMScsICdoZXgnKVxuLy8gVXNlZCB0byByZXByZXNlbnQgdGhlIGFic2VuY2Ugb2YgYSB2YWx1ZVxudmFyIFZBTFVFX1VJTlQ2NF9NQVggPSBCdWZmZXIuZnJvbSgnZmZmZmZmZmZmZmZmZmZmZicsICdoZXgnKVxudmFyIEJMQU5LX09VVFBVVCA9IHtcbiAgc2NyaXB0OiBFTVBUWV9TQ1JJUFQsXG4gIHZhbHVlQnVmZmVyOiBWQUxVRV9VSU5UNjRfTUFYXG59XG5cblRyYW5zYWN0aW9uLkRBU0hfTk9STUFMID0gMFxuVHJhbnNhY3Rpb24uREFTSF9QUk9WSURFUl9SRUdJU1RFUiA9IDFcblRyYW5zYWN0aW9uLkRBU0hfUFJPVklERVJfVVBEQVRFX1NFUlZJQ0UgPSAyXG5UcmFuc2FjdGlvbi5EQVNIX1BST1ZJREVSX1VQREFURV9SRUdJU1RSQVIgPSAzXG5UcmFuc2FjdGlvbi5EQVNIX1BST1ZJREVSX1VQREFURV9SRVZPS0UgPSA0XG5UcmFuc2FjdGlvbi5EQVNIX0NPSU5CQVNFID0gNVxuVHJhbnNhY3Rpb24uREFTSF9RVU9SVU1fQ09NTUlUTUVOVCA9IDZcblxuVHJhbnNhY3Rpb24uZnJvbUJ1ZmZlciA9IGZ1bmN0aW9uIChidWZmZXIsIG5ldHdvcmsgPSBuZXR3b3Jrcy5iaXRjb2luLCBfX25vU3RyaWN0KSB7XG4gIGxldCBidWZmZXJSZWFkZXIgPSBuZXcgQnVmZmVyUmVhZGVyKGJ1ZmZlcilcblxuICBsZXQgdHggPSBuZXcgVHJhbnNhY3Rpb24obmV0d29yaylcbiAgdHgudmVyc2lvbiA9IGJ1ZmZlclJlYWRlci5yZWFkSW50MzIoKVxuXG4gIGlmIChjb2lucy5pc1pjYXNoKG5ldHdvcmspKSB7XG4gICAgLy8gU3BsaXQgdGhlIGhlYWRlciBpbnRvIGZPdmVyd2ludGVyZWQgYW5kIG5WZXJzaW9uXG4gICAgdHgub3ZlcndpbnRlcmVkID0gdHgudmVyc2lvbiA+Pj4gMzEgIC8vIE11c3QgYmUgMSBmb3IgdmVyc2lvbiAzIGFuZCB1cFxuICAgIHR4LnZlcnNpb24gPSB0eC52ZXJzaW9uICYgMHgwN0ZGRkZGRkYgIC8vIDMgZm9yIG92ZXJ3aW50ZXJcbiAgICBpZiAoIW5ldHdvcmsuY29uc2Vuc3VzQnJhbmNoSWQuaGFzT3duUHJvcGVydHkodHgudmVyc2lvbikpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignVW5zdXBwb3J0ZWQgWmNhc2ggdHJhbnNhY3Rpb24nKVxuICAgIH1cbiAgICB0eC5jb25zZW5zdXNCcmFuY2hJZCA9IG5ldHdvcmsuY29uc2Vuc3VzQnJhbmNoSWRbdHgudmVyc2lvbl1cbiAgICBidWZmZXJSZWFkZXIgPSBuZXcgWmNhc2hCdWZmZXJSZWFkZXIoXG4gICAgICBidWZmZXJSZWFkZXIuYnVmZmVyLFxuICAgICAgYnVmZmVyUmVhZGVyLm9mZnNldCxcbiAgICAgIHR4LnZlcnNpb25cbiAgICApXG4gIH1cblxuICBpZiAoY29pbnMuaXNEYXNoKG5ldHdvcmspKSB7XG4gICAgdHgudHlwZSA9IHR4LnZlcnNpb24gPj4gMTZcbiAgICB0eC52ZXJzaW9uID0gdHgudmVyc2lvbiAmIDB4ZmZmZlxuICAgIGlmICh0eC52ZXJzaW9uID09PSAzICYmICh0eC50eXBlIDwgVHJhbnNhY3Rpb24uREFTSF9OT1JNQUwgfHwgdHgudHlwZSA+IFRyYW5zYWN0aW9uLkRBU0hfUVVPUlVNX0NPTU1JVE1FTlQpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ1Vuc3VwcG9ydGVkIERhc2ggdHJhbnNhY3Rpb24gdHlwZScpXG4gICAgfVxuICB9XG5cbiAgdmFyIG1hcmtlciA9IGJ1ZmZlclJlYWRlci5yZWFkVUludDgoKVxuICB2YXIgZmxhZyA9IGJ1ZmZlclJlYWRlci5yZWFkVUludDgoKVxuXG4gIHZhciBoYXNXaXRuZXNzZXMgPSBmYWxzZVxuICBpZiAobWFya2VyID09PSBUcmFuc2FjdGlvbi5BRFZBTkNFRF9UUkFOU0FDVElPTl9NQVJLRVIgJiZcbiAgICAgIGZsYWcgPT09IFRyYW5zYWN0aW9uLkFEVkFOQ0VEX1RSQU5TQUNUSU9OX0ZMQUcgJiZcbiAgICAgICFjb2lucy5pc1pjYXNoKG5ldHdvcmspKSB7XG4gICAgaGFzV2l0bmVzc2VzID0gdHJ1ZVxuICB9IGVsc2Uge1xuICAgIGJ1ZmZlclJlYWRlci5vZmZzZXQgLT0gMlxuICB9XG5cbiAgaWYgKHR4LmlzT3ZlcndpbnRlckNvbXBhdGlibGUoKSkge1xuICAgIHR4LnZlcnNpb25Hcm91cElkID0gYnVmZmVyUmVhZGVyLnJlYWRVSW50MzIoKVxuICB9XG5cbiAgdmFyIHZpbkxlbiA9IGJ1ZmZlclJlYWRlci5yZWFkVmFySW50KClcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCB2aW5MZW47ICsraSkge1xuICAgIHR4Lmlucy5wdXNoKHtcbiAgICAgIGhhc2g6IGJ1ZmZlclJlYWRlci5yZWFkU2xpY2UoMzIpLFxuICAgICAgaW5kZXg6IGJ1ZmZlclJlYWRlci5yZWFkVUludDMyKCksXG4gICAgICBzY3JpcHQ6IGJ1ZmZlclJlYWRlci5yZWFkVmFyU2xpY2UoKSxcbiAgICAgIHNlcXVlbmNlOiBidWZmZXJSZWFkZXIucmVhZFVJbnQzMigpLFxuICAgICAgd2l0bmVzczogRU1QVFlfV0lUTkVTU1xuICAgIH0pXG4gIH1cblxuICB2YXIgdm91dExlbiA9IGJ1ZmZlclJlYWRlci5yZWFkVmFySW50KClcbiAgZm9yIChpID0gMDsgaSA8IHZvdXRMZW47ICsraSkge1xuICAgIHR4Lm91dHMucHVzaCh7XG4gICAgICB2YWx1ZTogYnVmZmVyUmVhZGVyLnJlYWRVSW50NjQoKSxcbiAgICAgIHNjcmlwdDogYnVmZmVyUmVhZGVyLnJlYWRWYXJTbGljZSgpXG4gICAgfSlcbiAgfVxuXG4gIGlmIChoYXNXaXRuZXNzZXMpIHtcbiAgICBmb3IgKGkgPSAwOyBpIDwgdmluTGVuOyArK2kpIHtcbiAgICAgIHR4Lmluc1tpXS53aXRuZXNzID0gYnVmZmVyUmVhZGVyLnJlYWRWZWN0b3IoKVxuICAgIH1cblxuICAgIC8vIHdhcyB0aGlzIHBvaW50bGVzcz9cbiAgICBpZiAoIXR4Lmhhc1dpdG5lc3NlcygpKSB0aHJvdyBuZXcgRXJyb3IoJ1RyYW5zYWN0aW9uIGhhcyBzdXBlcmZsdW91cyB3aXRuZXNzIGRhdGEnKVxuICB9XG5cbiAgdHgubG9ja3RpbWUgPSBidWZmZXJSZWFkZXIucmVhZFVJbnQzMigpXG5cbiAgaWYgKGNvaW5zLmlzWmNhc2gobmV0d29yaykpIHtcbiAgICBpZiAodHguaXNPdmVyd2ludGVyQ29tcGF0aWJsZSgpKSB7XG4gICAgICB0eC5leHBpcnlIZWlnaHQgPSBidWZmZXJSZWFkZXIucmVhZFVJbnQzMigpXG4gICAgfVxuXG4gICAgaWYgKHR4LmlzU2FwbGluZ0NvbXBhdGlibGUoKSkge1xuICAgICAgdHgudmFsdWVCYWxhbmNlID0gYnVmZmVyUmVhZGVyLnJlYWRJbnQ2NCgpXG4gICAgICB2YXIgblNoaWVsZGVkU3BlbmQgPSBidWZmZXJSZWFkZXIucmVhZFZhckludCgpXG4gICAgICBmb3IgKGkgPSAwOyBpIDwgblNoaWVsZGVkU3BlbmQ7ICsraSkge1xuICAgICAgICB0eC52U2hpZWxkZWRTcGVuZC5wdXNoKGJ1ZmZlclJlYWRlci5yZWFkU2hpZWxkZWRTcGVuZCgpKVxuICAgICAgfVxuXG4gICAgICB2YXIgblNoaWVsZGVkT3V0cHV0ID0gYnVmZmVyUmVhZGVyLnJlYWRWYXJJbnQoKVxuICAgICAgZm9yIChpID0gMDsgaSA8IG5TaGllbGRlZE91dHB1dDsgKytpKSB7XG4gICAgICAgIHR4LnZTaGllbGRlZE91dHB1dC5wdXNoKGJ1ZmZlclJlYWRlci5yZWFkU2hpZWxkZWRPdXRwdXQoKSlcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAodHguc3VwcG9ydHNKb2luU3BsaXRzKCkpIHtcbiAgICAgIHZhciBqb2luU3BsaXRzTGVuID0gYnVmZmVyUmVhZGVyLnJlYWRWYXJJbnQoKVxuICAgICAgZm9yIChpID0gMDsgaSA8IGpvaW5TcGxpdHNMZW47ICsraSkge1xuICAgICAgICB0eC5qb2luc3BsaXRzLnB1c2goYnVmZmVyUmVhZGVyLnJlYWRKb2luU3BsaXQoKSlcbiAgICAgIH1cbiAgICAgIGlmIChqb2luU3BsaXRzTGVuID4gMCkge1xuICAgICAgICB0eC5qb2luc3BsaXRQdWJrZXkgPSBidWZmZXJSZWFkZXIucmVhZFNsaWNlKDMyKVxuICAgICAgICB0eC5qb2luc3BsaXRTaWcgPSBidWZmZXJSZWFkZXIucmVhZFNsaWNlKDY0KVxuICAgICAgfVxuICAgIH1cblxuICAgIGlmICh0eC5pc1NhcGxpbmdDb21wYXRpYmxlKCkgJiZcbiAgICAgIHR4LnZTaGllbGRlZFNwZW5kLmxlbmd0aCArIHR4LnZTaGllbGRlZE91dHB1dC5sZW5ndGggPiAwKSB7XG4gICAgICB0eC5iaW5kaW5nU2lnID0gYnVmZmVyUmVhZGVyLnJlYWRTbGljZSg2NClcbiAgICB9XG4gIH1cblxuICBpZiAodHguaXNEYXNoU3BlY2lhbFRyYW5zYWN0aW9uKCkpIHtcbiAgICB0eC5leHRyYVBheWxvYWQgPSBidWZmZXJSZWFkZXIucmVhZFZhclNsaWNlKClcbiAgfVxuXG4gIHR4Lm5ldHdvcmsgPSBuZXR3b3JrXG5cbiAgaWYgKF9fbm9TdHJpY3QpIHJldHVybiB0eFxuICBpZiAoYnVmZmVyUmVhZGVyLm9mZnNldCAhPT0gYnVmZmVyLmxlbmd0aCkgdGhyb3cgbmV3IEVycm9yKCdUcmFuc2FjdGlvbiBoYXMgdW5leHBlY3RlZCBkYXRhJylcblxuICByZXR1cm4gdHhcbn1cblxuVHJhbnNhY3Rpb24uZnJvbUhleCA9IGZ1bmN0aW9uIChoZXgsIG5ldHdvcmspIHtcbiAgcmV0dXJuIFRyYW5zYWN0aW9uLmZyb21CdWZmZXIoQnVmZmVyLmZyb20oaGV4LCAnaGV4JyksIG5ldHdvcmspXG59XG5cblRyYW5zYWN0aW9uLmlzQ29pbmJhc2VIYXNoID0gZnVuY3Rpb24gKGJ1ZmZlcikge1xuICB0eXBlZm9yY2UodHlwZXMuSGFzaDI1NmJpdCwgYnVmZmVyKVxuICBmb3IgKHZhciBpID0gMDsgaSA8IDMyOyArK2kpIHtcbiAgICBpZiAoYnVmZmVyW2ldICE9PSAwKSByZXR1cm4gZmFsc2VcbiAgfVxuICByZXR1cm4gdHJ1ZVxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuaXNTYXBsaW5nQ29tcGF0aWJsZSA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIGNvaW5zLmlzWmNhc2godGhpcy5uZXR3b3JrKSAmJiB0aGlzLnZlcnNpb24gPj0gemNhc2hWZXJzaW9uLlNBUExJTkdcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmlzT3ZlcndpbnRlckNvbXBhdGlibGUgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiBjb2lucy5pc1pjYXNoKHRoaXMubmV0d29yaykgJiYgdGhpcy52ZXJzaW9uID49IHpjYXNoVmVyc2lvbi5PVkVSV0lOVEVSXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5zdXBwb3J0c0pvaW5TcGxpdHMgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiBjb2lucy5pc1pjYXNoKHRoaXMubmV0d29yaykgJiYgdGhpcy52ZXJzaW9uID49IHpjYXNoVmVyc2lvbi5KT0lOU1BMSVRTX1NVUFBPUlRcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLnZlcnNpb25TdXBwb3J0c0Rhc2hTcGVjaWFsVHJhbnNhY3Rpb25zID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gY29pbnMuaXNEYXNoKHRoaXMubmV0d29yaykgJiYgdGhpcy52ZXJzaW9uID49IDNcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmlzRGFzaFNwZWNpYWxUcmFuc2FjdGlvbiA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIHRoaXMudmVyc2lvblN1cHBvcnRzRGFzaFNwZWNpYWxUcmFuc2FjdGlvbnMoKSAmJiB0aGlzLnR5cGUgIT09IFRyYW5zYWN0aW9uLkRBU0hfTk9STUFMXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5pc0NvaW5iYXNlID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gdGhpcy5pbnMubGVuZ3RoID09PSAxICYmIFRyYW5zYWN0aW9uLmlzQ29pbmJhc2VIYXNoKHRoaXMuaW5zWzBdLmhhc2gpXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5hZGRJbnB1dCA9IGZ1bmN0aW9uIChoYXNoLCBpbmRleCwgc2VxdWVuY2UsIHNjcmlwdFNpZykge1xuICB0eXBlZm9yY2UodHlwZXMudHVwbGUoXG4gICAgdHlwZXMuSGFzaDI1NmJpdCxcbiAgICB0eXBlcy5VSW50MzIsXG4gICAgdHlwZXMubWF5YmUodHlwZXMuVUludDMyKSxcbiAgICB0eXBlcy5tYXliZSh0eXBlcy5CdWZmZXIpXG4gICksIGFyZ3VtZW50cylcblxuICBpZiAodHlwZXMuTnVsbChzZXF1ZW5jZSkpIHtcbiAgICBzZXF1ZW5jZSA9IFRyYW5zYWN0aW9uLkRFRkFVTFRfU0VRVUVOQ0VcbiAgfVxuXG4gIC8vIEFkZCB0aGUgaW5wdXQgYW5kIHJldHVybiB0aGUgaW5wdXQncyBpbmRleFxuICByZXR1cm4gKHRoaXMuaW5zLnB1c2goe1xuICAgIGhhc2g6IGhhc2gsXG4gICAgaW5kZXg6IGluZGV4LFxuICAgIHNjcmlwdDogc2NyaXB0U2lnIHx8IEVNUFRZX1NDUklQVCxcbiAgICBzZXF1ZW5jZTogc2VxdWVuY2UsXG4gICAgd2l0bmVzczogRU1QVFlfV0lUTkVTU1xuICB9KSAtIDEpXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5hZGRPdXRwdXQgPSBmdW5jdGlvbiAoc2NyaXB0UHViS2V5LCB2YWx1ZSkge1xuICB0eXBlZm9yY2UodHlwZXMudHVwbGUodHlwZXMuQnVmZmVyLCB0eXBlcy5TYXRvc2hpKSwgYXJndW1lbnRzKVxuXG4gIC8vIEFkZCB0aGUgb3V0cHV0IGFuZCByZXR1cm4gdGhlIG91dHB1dCdzIGluZGV4XG4gIHJldHVybiAodGhpcy5vdXRzLnB1c2goe1xuICAgIHNjcmlwdDogc2NyaXB0UHViS2V5LFxuICAgIHZhbHVlOiB2YWx1ZVxuICB9KSAtIDEpXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5oYXNXaXRuZXNzZXMgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiB0aGlzLmlucy5zb21lKGZ1bmN0aW9uICh4KSB7XG4gICAgcmV0dXJuIHgud2l0bmVzcy5sZW5ndGggIT09IDBcbiAgfSlcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLndlaWdodCA9IGZ1bmN0aW9uICgpIHtcbiAgdmFyIGJhc2UgPSB0aGlzLl9fYnl0ZUxlbmd0aChmYWxzZSlcbiAgdmFyIHRvdGFsID0gdGhpcy5fX2J5dGVMZW5ndGgodHJ1ZSlcbiAgcmV0dXJuIGJhc2UgKiAzICsgdG90YWxcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLnZpcnR1YWxTaXplID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gTWF0aC5jZWlsKHRoaXMud2VpZ2h0KCkgLyA0KVxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuYnl0ZUxlbmd0aCA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIHRoaXMuX19ieXRlTGVuZ3RoKHRydWUpXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5nZXRTaGllbGRlZFNwZW5kQnl0ZUxlbmd0aCA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKCF0aGlzLmlzU2FwbGluZ0NvbXBhdGlibGUoKSkge1xuICAgIHJldHVybiAwXG4gIH1cblxuICB2YXIgYnl0ZUxlbmd0aCA9IDBcbiAgYnl0ZUxlbmd0aCArPSB2YXJ1aW50LmVuY29kaW5nTGVuZ3RoKHRoaXMudlNoaWVsZGVkU3BlbmQubGVuZ3RoKSAgLy8gblNoaWVsZGVkU3BlbmRcbiAgYnl0ZUxlbmd0aCArPSAoMzg0ICogdGhpcy52U2hpZWxkZWRTcGVuZC5sZW5ndGgpICAvLyB2U2hpZWxkZWRTcGVuZFxuICByZXR1cm4gYnl0ZUxlbmd0aFxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuZ2V0U2hpZWxkZWRPdXRwdXRCeXRlTGVuZ3RoID0gZnVuY3Rpb24gKCkge1xuICBpZiAoIXRoaXMuaXNTYXBsaW5nQ29tcGF0aWJsZSgpKSB7XG4gICAgcmV0dXJuIDBcbiAgfVxuICB2YXIgYnl0ZUxlbmd0aCA9IDBcbiAgYnl0ZUxlbmd0aCArPSB2YXJ1aW50LmVuY29kaW5nTGVuZ3RoKHRoaXMudlNoaWVsZGVkT3V0cHV0Lmxlbmd0aCkgIC8vIG5TaGllbGRlZE91dHB1dFxuICBieXRlTGVuZ3RoICs9ICg5NDggKiB0aGlzLnZTaGllbGRlZE91dHB1dC5sZW5ndGgpICAvLyB2U2hpZWxkZWRPdXRwdXRcbiAgcmV0dXJuIGJ5dGVMZW5ndGhcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmdldEpvaW5TcGxpdEJ5dGVMZW5ndGggPSBmdW5jdGlvbiAoKSB7XG4gIGlmICghdGhpcy5zdXBwb3J0c0pvaW5TcGxpdHMoKSkge1xuICAgIHJldHVybiAwXG4gIH1cbiAgdmFyIGpvaW5TcGxpdHNMZW4gPSB0aGlzLmpvaW5zcGxpdHMubGVuZ3RoXG4gIHZhciBieXRlTGVuZ3RoID0gMFxuICBieXRlTGVuZ3RoICs9IHZhcnVpbnQuZW5jb2RpbmdMZW5ndGgoam9pblNwbGl0c0xlbikgIC8vIHZKb2luU3BsaXRcblxuICBpZiAoam9pblNwbGl0c0xlbiA+IDApIHtcbiAgICAvLyBCb3RoIHByZSBhbmQgcG9zdCBTYXBsaW5nIEpvaW5TcGxpdHMgYXJlIGVuY29kZWQgd2l0aCB0aGUgZm9sbG93aW5nIGRhdGE6XG4gICAgLy8gOCB2cHViX29sZCwgOCB2cHViX25ldywgMzIgYW5jaG9yLCBqb2luU3BsaXRzTGVuICogMzIgbnVsbGlmaWVycywgam9pblNwbGl0c0xlbiAqIDMyIGNvbW1pdG1lbnRzLCAzMiBlcGhlbWVyYWxLZXlcbiAgICAvLyAzMiBlcGhlbWVyYWxLZXksIDMyIHJhbmRvbVNlZWQsIGpvaW5zcGxpdC5tYWNzLmxlbmd0aCAqIDMyIHZtYWNzXG4gICAgaWYgKHRoaXMuaXNTYXBsaW5nQ29tcGF0aWJsZSgpKSB7XG4gICAgICBieXRlTGVuZ3RoICs9IDE2OTggKiBqb2luU3BsaXRzTGVuICAvLyB2Sm9pblNwbGl0IHVzaW5nIEpTRGVzY3JpcHRpb25Hcm90aDE2XG4gICAgfSBlbHNlIHtcbiAgICAgIGJ5dGVMZW5ndGggKz0gMTgwMiAqIGpvaW5TcGxpdHNMZW4gIC8vIHZKb2luU3BsaXQgdXNpbmcgSlNEZXNjcmlwdGlvblBIR1IxM1xuICAgIH1cbiAgICBieXRlTGVuZ3RoICs9IDMyICAvLyBqb2luU3BsaXRQdWJLZXlcbiAgICBieXRlTGVuZ3RoICs9IDY0ICAvLyBqb2luU3BsaXRTaWdcbiAgfVxuXG4gIHJldHVybiBieXRlTGVuZ3RoXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS56Y2FzaFRyYW5zYWN0aW9uQnl0ZUxlbmd0aCA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKCFjb2lucy5pc1pjYXNoKHRoaXMubmV0d29yaykpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ3pjYXNoVHJhbnNhY3Rpb25CeXRlTGVuZ3RoIGNhbiBvbmx5IGJlIGNhbGxlZCB3aGVuIHVzaW5nIFpjYXNoIG5ldHdvcmsnKVxuICB9XG4gIHZhciBieXRlTGVuZ3RoID0gMFxuICBieXRlTGVuZ3RoICs9IDQgIC8vIEhlYWRlclxuICBpZiAodGhpcy5pc092ZXJ3aW50ZXJDb21wYXRpYmxlKCkpIHtcbiAgICBieXRlTGVuZ3RoICs9IDQgIC8vIG5WZXJzaW9uR3JvdXBJZFxuICB9XG4gIGJ5dGVMZW5ndGggKz0gdmFydWludC5lbmNvZGluZ0xlbmd0aCh0aGlzLmlucy5sZW5ndGgpICAvLyB0eF9pbl9jb3VudFxuICBieXRlTGVuZ3RoICs9IHRoaXMuaW5zLnJlZHVjZShmdW5jdGlvbiAoc3VtLCBpbnB1dCkgeyByZXR1cm4gc3VtICsgNDAgKyB2YXJTbGljZVNpemUoaW5wdXQuc2NyaXB0KSB9LCAwKSAgLy8gdHhfaW5cbiAgYnl0ZUxlbmd0aCArPSB2YXJ1aW50LmVuY29kaW5nTGVuZ3RoKHRoaXMub3V0cy5sZW5ndGgpICAvLyB0eF9vdXRfY291bnRcbiAgYnl0ZUxlbmd0aCArPSB0aGlzLm91dHMucmVkdWNlKGZ1bmN0aW9uIChzdW0sIG91dHB1dCkgeyByZXR1cm4gc3VtICsgOCArIHZhclNsaWNlU2l6ZShvdXRwdXQuc2NyaXB0KSB9LCAwKSAgLy8gdHhfb3V0XG4gIGJ5dGVMZW5ndGggKz0gNCAgLy8gbG9ja190aW1lXG4gIGlmICh0aGlzLmlzT3ZlcndpbnRlckNvbXBhdGlibGUoKSkge1xuICAgIGJ5dGVMZW5ndGggKz0gNCAgLy8gbkV4cGlyeUhlaWdodFxuICB9XG4gIGlmICh0aGlzLmlzU2FwbGluZ0NvbXBhdGlibGUoKSkge1xuICAgIGJ5dGVMZW5ndGggKz0gOCAgLy8gdmFsdWVCYWxhbmNlXG4gICAgYnl0ZUxlbmd0aCArPSB0aGlzLmdldFNoaWVsZGVkU3BlbmRCeXRlTGVuZ3RoKClcbiAgICBieXRlTGVuZ3RoICs9IHRoaXMuZ2V0U2hpZWxkZWRPdXRwdXRCeXRlTGVuZ3RoKClcbiAgfVxuICBpZiAodGhpcy5zdXBwb3J0c0pvaW5TcGxpdHMoKSkge1xuICAgIGJ5dGVMZW5ndGggKz0gdGhpcy5nZXRKb2luU3BsaXRCeXRlTGVuZ3RoKClcbiAgfVxuICBpZiAodGhpcy5pc1NhcGxpbmdDb21wYXRpYmxlKCkgJiZcbiAgICB0aGlzLnZTaGllbGRlZFNwZW5kLmxlbmd0aCArIHRoaXMudlNoaWVsZGVkT3V0cHV0Lmxlbmd0aCA+IDApIHtcbiAgICBieXRlTGVuZ3RoICs9IDY0ICAvLyBiaW5kaW5nU2lnXG4gIH1cbiAgcmV0dXJuIGJ5dGVMZW5ndGhcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLl9fYnl0ZUxlbmd0aCA9IGZ1bmN0aW9uIChfX2FsbG93V2l0bmVzcykge1xuICB2YXIgaGFzV2l0bmVzc2VzID0gX19hbGxvd1dpdG5lc3MgJiYgdGhpcy5oYXNXaXRuZXNzZXMoKVxuXG4gIGlmIChjb2lucy5pc1pjYXNoKHRoaXMubmV0d29yaykpIHtcbiAgICByZXR1cm4gdGhpcy56Y2FzaFRyYW5zYWN0aW9uQnl0ZUxlbmd0aCgpXG4gIH1cblxuICByZXR1cm4gKFxuICAgIChoYXNXaXRuZXNzZXMgPyAxMCA6IDgpICtcbiAgICB2YXJ1aW50LmVuY29kaW5nTGVuZ3RoKHRoaXMuaW5zLmxlbmd0aCkgK1xuICAgIHZhcnVpbnQuZW5jb2RpbmdMZW5ndGgodGhpcy5vdXRzLmxlbmd0aCkgK1xuICAgIHRoaXMuaW5zLnJlZHVjZShmdW5jdGlvbiAoc3VtLCBpbnB1dCkgeyByZXR1cm4gc3VtICsgNDAgKyB2YXJTbGljZVNpemUoaW5wdXQuc2NyaXB0KSB9LCAwKSArXG4gICAgdGhpcy5vdXRzLnJlZHVjZShmdW5jdGlvbiAoc3VtLCBvdXRwdXQpIHsgcmV0dXJuIHN1bSArIDggKyB2YXJTbGljZVNpemUob3V0cHV0LnNjcmlwdCkgfSwgMCkgK1xuICAgICh0aGlzLmlzRGFzaFNwZWNpYWxUcmFuc2FjdGlvbigpID8gdmFyU2xpY2VTaXplKHRoaXMuZXh0cmFQYXlsb2FkKSA6IDApICtcbiAgICAoaGFzV2l0bmVzc2VzID8gdGhpcy5pbnMucmVkdWNlKGZ1bmN0aW9uIChzdW0sIGlucHV0KSB7IHJldHVybiBzdW0gKyB2ZWN0b3JTaXplKGlucHV0LndpdG5lc3MpIH0sIDApIDogMClcbiAgKVxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuY2xvbmUgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBuZXdUeCA9IG5ldyBUcmFuc2FjdGlvbih0aGlzLm5ldHdvcmspXG4gIG5ld1R4LnZlcnNpb24gPSB0aGlzLnZlcnNpb25cbiAgbmV3VHgubG9ja3RpbWUgPSB0aGlzLmxvY2t0aW1lXG4gIG5ld1R4Lm5ldHdvcmsgPSB0aGlzLm5ldHdvcmtcblxuICBpZiAoY29pbnMuaXNEYXNoKHRoaXMubmV0d29yaykpIHtcbiAgICBuZXdUeC50eXBlID0gdGhpcy50eXBlXG4gICAgbmV3VHguZXh0cmFQYXlsb2FkID0gdGhpcy5leHRyYVBheWxvYWRcbiAgfVxuXG4gIGlmIChjb2lucy5pc1pjYXNoKHRoaXMubmV0d29yaykpIHtcbiAgICBuZXdUeC5jb25zZW5zdXNCcmFuY2hJZCA9IHRoaXMuY29uc2Vuc3VzQnJhbmNoSWRcbiAgfVxuICBpZiAodGhpcy5pc092ZXJ3aW50ZXJDb21wYXRpYmxlKCkpIHtcbiAgICBuZXdUeC5vdmVyd2ludGVyZWQgPSB0aGlzLm92ZXJ3aW50ZXJlZFxuICAgIG5ld1R4LnZlcnNpb25Hcm91cElkID0gdGhpcy52ZXJzaW9uR3JvdXBJZFxuICAgIG5ld1R4LmV4cGlyeUhlaWdodCA9IHRoaXMuZXhwaXJ5SGVpZ2h0XG4gIH1cbiAgaWYgKHRoaXMuaXNTYXBsaW5nQ29tcGF0aWJsZSgpKSB7XG4gICAgbmV3VHgudmFsdWVCYWxhbmNlID0gdGhpcy52YWx1ZUJhbGFuY2VcbiAgfVxuXG4gIG5ld1R4LmlucyA9IHRoaXMuaW5zLm1hcChmdW5jdGlvbiAodHhJbikge1xuICAgIHJldHVybiB7XG4gICAgICBoYXNoOiB0eEluLmhhc2gsXG4gICAgICBpbmRleDogdHhJbi5pbmRleCxcbiAgICAgIHNjcmlwdDogdHhJbi5zY3JpcHQsXG4gICAgICBzZXF1ZW5jZTogdHhJbi5zZXF1ZW5jZSxcbiAgICAgIHdpdG5lc3M6IHR4SW4ud2l0bmVzc1xuICAgIH1cbiAgfSlcblxuICBuZXdUeC5vdXRzID0gdGhpcy5vdXRzLm1hcChmdW5jdGlvbiAodHhPdXQpIHtcbiAgICByZXR1cm4ge1xuICAgICAgc2NyaXB0OiB0eE91dC5zY3JpcHQsXG4gICAgICB2YWx1ZTogdHhPdXQudmFsdWVcbiAgICB9XG4gIH0pXG4gIGlmICh0aGlzLmlzU2FwbGluZ0NvbXBhdGlibGUoKSkge1xuICAgIG5ld1R4LnZTaGllbGRlZFNwZW5kID0gdGhpcy52U2hpZWxkZWRTcGVuZC5tYXAoZnVuY3Rpb24gKHNoaWVsZGVkU3BlbmQpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGN2OiBzaGllbGRlZFNwZW5kLmN2LFxuICAgICAgICBhbmNob3I6IHNoaWVsZGVkU3BlbmQuYW5jaG9yLFxuICAgICAgICBudWxsaWZpZXI6IHNoaWVsZGVkU3BlbmQubnVsbGlmaWVyLFxuICAgICAgICByazogc2hpZWxkZWRTcGVuZC5yayxcbiAgICAgICAgemtwcm9vZjogc2hpZWxkZWRTcGVuZC56a3Byb29mLFxuICAgICAgICBzcGVuZEF1dGhTaWc6IHNoaWVsZGVkU3BlbmQuc3BlbmRBdXRoU2lnXG4gICAgICB9XG4gICAgfSlcblxuICAgIG5ld1R4LnZTaGllbGRlZE91dHB1dCA9IHRoaXMudlNoaWVsZGVkT3V0cHV0Lm1hcChmdW5jdGlvbiAoc2hpZWxkZWRPdXRwdXQpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGN2OiBzaGllbGRlZE91dHB1dC5jdixcbiAgICAgICAgY211OiBzaGllbGRlZE91dHB1dC5jbXUsXG4gICAgICAgIGVwaGVtZXJhbEtleTogc2hpZWxkZWRPdXRwdXQuZXBoZW1lcmFsS2V5LFxuICAgICAgICBlbmNDaXBoZXJ0ZXh0OiBzaGllbGRlZE91dHB1dC5lbmNDaXBoZXJ0ZXh0LFxuICAgICAgICBvdXRDaXBoZXJ0ZXh0OiBzaGllbGRlZE91dHB1dC5vdXRDaXBoZXJ0ZXh0LFxuICAgICAgICB6a3Byb29mOiBzaGllbGRlZE91dHB1dC56a3Byb29mXG4gICAgICB9XG4gICAgfSlcbiAgfVxuXG4gIGlmICh0aGlzLnN1cHBvcnRzSm9pblNwbGl0cygpKSB7XG4gICAgbmV3VHguam9pbnNwbGl0cyA9IHRoaXMuam9pbnNwbGl0cy5tYXAoZnVuY3Rpb24gKHR4Sm9pbnNwbGl0KSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICB2cHViT2xkOiB0eEpvaW5zcGxpdC52cHViT2xkLFxuICAgICAgICB2cHViTmV3OiB0eEpvaW5zcGxpdC52cHViTmV3LFxuICAgICAgICBhbmNob3I6IHR4Sm9pbnNwbGl0LmFuY2hvcixcbiAgICAgICAgbnVsbGlmaWVyczogdHhKb2luc3BsaXQubnVsbGlmaWVycyxcbiAgICAgICAgY29tbWl0bWVudHM6IHR4Sm9pbnNwbGl0LmNvbW1pdG1lbnRzLFxuICAgICAgICBlcGhlbWVyYWxLZXk6IHR4Sm9pbnNwbGl0LmVwaGVtZXJhbEtleSxcbiAgICAgICAgcmFuZG9tU2VlZDogdHhKb2luc3BsaXQucmFuZG9tU2VlZCxcbiAgICAgICAgbWFjczogdHhKb2luc3BsaXQubWFjcyxcbiAgICAgICAgemtwcm9vZjogdHhKb2luc3BsaXQuemtwcm9vZixcbiAgICAgICAgY2lwaGVydGV4dHM6IHR4Sm9pbnNwbGl0LmNpcGhlcnRleHRzXG4gICAgICB9XG4gICAgfSlcblxuICAgIG5ld1R4LmpvaW5zcGxpdFB1YmtleSA9IHRoaXMuam9pbnNwbGl0UHVia2V5XG4gICAgbmV3VHguam9pbnNwbGl0U2lnID0gdGhpcy5qb2luc3BsaXRTaWdcbiAgfVxuXG4gIGlmICh0aGlzLmlzU2FwbGluZ0NvbXBhdGlibGUoKSAmJiB0aGlzLnZTaGllbGRlZFNwZW5kLmxlbmd0aCArIHRoaXMudlNoaWVsZGVkT3V0cHV0Lmxlbmd0aCA+IDApIHtcbiAgICBuZXdUeC5iaW5kaW5nU2lnID0gdGhpcy5iaW5kaW5nU2lnXG4gIH1cblxuICByZXR1cm4gbmV3VHhcbn1cblxuLyoqXG4gKiBHZXQgWmNhc2ggaGVhZGVyIG9yIHZlcnNpb25cbiAqIEByZXR1cm5zIHtudW1iZXJ9XG4gKi9cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5nZXRIZWFkZXIgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBtYXNrID0gKHRoaXMub3ZlcndpbnRlcmVkID8gMSA6IDApXG4gIHZhciBoZWFkZXIgPSB0aGlzLnZlcnNpb24gfCAobWFzayA8PCAzMSlcbiAgcmV0dXJuIGhlYWRlclxufVxuXG4vKipcbiAqIEhhc2ggdHJhbnNhY3Rpb24gZm9yIHNpZ25pbmcgYSBzcGVjaWZpYyBpbnB1dC5cbiAqXG4gKiBCaXRjb2luIHVzZXMgYSBkaWZmZXJlbnQgaGFzaCBmb3IgZWFjaCBzaWduZWQgdHJhbnNhY3Rpb24gaW5wdXQuXG4gKiBUaGlzIG1ldGhvZCBjb3BpZXMgdGhlIHRyYW5zYWN0aW9uLCBtYWtlcyB0aGUgbmVjZXNzYXJ5IGNoYW5nZXMgYmFzZWQgb24gdGhlXG4gKiBoYXNoVHlwZSwgYW5kIHRoZW4gaGFzaGVzIHRoZSByZXN1bHQuXG4gKiBUaGlzIGhhc2ggY2FuIHRoZW4gYmUgdXNlZCB0byBzaWduIHRoZSBwcm92aWRlZCB0cmFuc2FjdGlvbiBpbnB1dC5cbiAqL1xuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmhhc2hGb3JTaWduYXR1cmUgPSBmdW5jdGlvbiAoaW5JbmRleCwgcHJldk91dFNjcmlwdCwgaGFzaFR5cGUpIHtcbiAgdHlwZWZvcmNlKHR5cGVzLnR1cGxlKHR5cGVzLlVJbnQzMiwgdHlwZXMuQnVmZmVyLCAvKiB0eXBlcy5VSW50OCAqLyB0eXBlcy5OdW1iZXIpLCBhcmd1bWVudHMpXG5cbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL2JpdGNvaW4vYml0Y29pbi9ibG9iL21hc3Rlci9zcmMvdGVzdC9zaWdoYXNoX3Rlc3RzLmNwcCNMMjlcbiAgaWYgKGluSW5kZXggPj0gdGhpcy5pbnMubGVuZ3RoKSByZXR1cm4gT05FXG5cbiAgLy8gaWdub3JlIE9QX0NPREVTRVBBUkFUT1JcbiAgdmFyIG91clNjcmlwdCA9IGJzY3JpcHQuY29tcGlsZShic2NyaXB0LmRlY29tcGlsZShwcmV2T3V0U2NyaXB0KS5maWx0ZXIoZnVuY3Rpb24gKHgpIHtcbiAgICByZXR1cm4geCAhPT0gb3Bjb2Rlcy5PUF9DT0RFU0VQQVJBVE9SXG4gIH0pKVxuXG4gIHZhciB0eFRtcCA9IHRoaXMuY2xvbmUoKVxuXG4gIC8vIFNJR0hBU0hfTk9ORTogaWdub3JlIGFsbCBvdXRwdXRzPyAod2lsZGNhcmQgcGF5ZWUpXG4gIGlmICgoaGFzaFR5cGUgJiAweDFmKSA9PT0gVHJhbnNhY3Rpb24uU0lHSEFTSF9OT05FKSB7XG4gICAgdHhUbXAub3V0cyA9IFtdXG5cbiAgICAvLyBpZ25vcmUgc2VxdWVuY2UgbnVtYmVycyAoZXhjZXB0IGF0IGluSW5kZXgpXG4gICAgdHhUbXAuaW5zLmZvckVhY2goZnVuY3Rpb24gKGlucHV0LCBpKSB7XG4gICAgICBpZiAoaSA9PT0gaW5JbmRleCkgcmV0dXJuXG5cbiAgICAgIGlucHV0LnNlcXVlbmNlID0gMFxuICAgIH0pXG5cbiAgICAvLyBTSUdIQVNIX1NJTkdMRTogaWdub3JlIGFsbCBvdXRwdXRzLCBleGNlcHQgYXQgdGhlIHNhbWUgaW5kZXg/XG4gIH0gZWxzZSBpZiAoKGhhc2hUeXBlICYgMHgxZikgPT09IFRyYW5zYWN0aW9uLlNJR0hBU0hfU0lOR0xFKSB7XG4gICAgLy8gaHR0cHM6Ly9naXRodWIuY29tL2JpdGNvaW4vYml0Y29pbi9ibG9iL21hc3Rlci9zcmMvdGVzdC9zaWdoYXNoX3Rlc3RzLmNwcCNMNjBcbiAgICBpZiAoaW5JbmRleCA+PSB0aGlzLm91dHMubGVuZ3RoKSByZXR1cm4gT05FXG5cbiAgICAvLyB0cnVuY2F0ZSBvdXRwdXRzIGFmdGVyXG4gICAgdHhUbXAub3V0cy5sZW5ndGggPSBpbkluZGV4ICsgMVxuXG4gICAgLy8gXCJibGFua1wiIG91dHB1dHMgYmVmb3JlXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBpbkluZGV4OyBpKyspIHtcbiAgICAgIHR4VG1wLm91dHNbaV0gPSBCTEFOS19PVVRQVVRcbiAgICB9XG5cbiAgICAvLyBpZ25vcmUgc2VxdWVuY2UgbnVtYmVycyAoZXhjZXB0IGF0IGluSW5kZXgpXG4gICAgdHhUbXAuaW5zLmZvckVhY2goZnVuY3Rpb24gKGlucHV0LCB5KSB7XG4gICAgICBpZiAoeSA9PT0gaW5JbmRleCkgcmV0dXJuXG5cbiAgICAgIGlucHV0LnNlcXVlbmNlID0gMFxuICAgIH0pXG4gIH1cblxuICAvLyBTSUdIQVNIX0FOWU9ORUNBTlBBWTogaWdub3JlIGlucHV0cyBlbnRpcmVseT9cbiAgaWYgKGhhc2hUeXBlICYgVHJhbnNhY3Rpb24uU0lHSEFTSF9BTllPTkVDQU5QQVkpIHtcbiAgICB0eFRtcC5pbnMgPSBbdHhUbXAuaW5zW2luSW5kZXhdXVxuICAgIHR4VG1wLmluc1swXS5zY3JpcHQgPSBvdXJTY3JpcHRcblxuICAgIC8vIFNJR0hBU0hfQUxMOiBvbmx5IGlnbm9yZSBpbnB1dCBzY3JpcHRzXG4gIH0gZWxzZSB7XG4gICAgLy8gXCJibGFua1wiIG90aGVycyBpbnB1dCBzY3JpcHRzXG4gICAgdHhUbXAuaW5zLmZvckVhY2goZnVuY3Rpb24gKGlucHV0KSB7IGlucHV0LnNjcmlwdCA9IEVNUFRZX1NDUklQVCB9KVxuICAgIHR4VG1wLmluc1tpbkluZGV4XS5zY3JpcHQgPSBvdXJTY3JpcHRcbiAgfVxuXG4gIC8vIHNlcmlhbGl6ZSBhbmQgaGFzaFxuICB2YXIgYnVmZmVyID0gQnVmZmVyLmFsbG9jVW5zYWZlKHR4VG1wLl9fYnl0ZUxlbmd0aChmYWxzZSkgKyA0KVxuICBidWZmZXIud3JpdGVJbnQzMkxFKGhhc2hUeXBlLCBidWZmZXIubGVuZ3RoIC0gNClcbiAgdHhUbXAuX190b0J1ZmZlcihidWZmZXIsIDAsIGZhbHNlKVxuXG4gIHJldHVybiBiY3J5cHRvLmhhc2gyNTYoYnVmZmVyKVxufVxuXG4vKipcbiAqIEJsYWtlMmIgaGFzaGluZyBhbGdvcml0aG0gZm9yIFpjYXNoXG4gKiBAcGFyYW0gYnVmZmVyVG9IYXNoXG4gKiBAcGFyYW0gcGVyc29uYWxpemF0aW9uXG4gKiBAcmV0dXJucyAyNTYtYml0IEJMQUtFMmIgaGFzaFxuICovXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuZ2V0Qmxha2UyYkhhc2ggPSBmdW5jdGlvbiAoYnVmZmVyVG9IYXNoLCBwZXJzb25hbGl6YXRpb24pIHtcbiAgdmFyIG91dCA9IEJ1ZmZlci5hbGxvY1Vuc2FmZSgzMilcbiAgcmV0dXJuIGJsYWtlMmIob3V0Lmxlbmd0aCwgbnVsbCwgbnVsbCwgQnVmZmVyLmZyb20ocGVyc29uYWxpemF0aW9uKSkudXBkYXRlKGJ1ZmZlclRvSGFzaCkuZGlnZXN0KG91dClcbn1cblxuLyoqXG4gKiBCdWlsZCBhIGhhc2ggZm9yIGFsbCBvciBub25lIG9mIHRoZSB0cmFuc2FjdGlvbiBpbnB1dHMgZGVwZW5kaW5nIG9uIHRoZSBoYXNodHlwZVxuICogQHBhcmFtIGhhc2hUeXBlXG4gKiBAcmV0dXJucyBkb3VibGUgU0hBLTI1NiwgMjU2LWJpdCBCTEFLRTJiIGhhc2ggb3IgMjU2LWJpdCB6ZXJvIGlmIGRvZXNuJ3QgYXBwbHlcbiAqL1xuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmdldFByZXZvdXRIYXNoID0gZnVuY3Rpb24gKGhhc2hUeXBlKSB7XG4gIGlmICghKGhhc2hUeXBlICYgVHJhbnNhY3Rpb24uU0lHSEFTSF9BTllPTkVDQU5QQVkpKSB7XG4gICAgdmFyIGJ1ZmZlcldyaXRlciA9IG5ldyBCdWZmZXJXcml0ZXIoQnVmZmVyLmFsbG9jVW5zYWZlKDM2ICogdGhpcy5pbnMubGVuZ3RoKSlcblxuICAgIHRoaXMuaW5zLmZvckVhY2goZnVuY3Rpb24gKHR4SW4pIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKHR4SW4uaGFzaClcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0eEluLmluZGV4KVxuICAgIH0pXG5cbiAgICBpZiAoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspKSB7XG4gICAgICByZXR1cm4gdGhpcy5nZXRCbGFrZTJiSGFzaChidWZmZXJXcml0ZXIuYnVmZmVyLCAnWmNhc2hQcmV2b3V0SGFzaCcpXG4gICAgfVxuICAgIHJldHVybiBiY3J5cHRvLmhhc2gyNTYoYnVmZmVyV3JpdGVyLmJ1ZmZlcilcbiAgfVxuICByZXR1cm4gWkVST1xufVxuXG4vKipcbiAqIEJ1aWxkIGEgaGFzaCBmb3IgYWxsIG9yIG5vbmUgb2YgdGhlIHRyYW5zYWN0aW9ucyBpbnB1dHMgc2VxdWVuY2UgbnVtYmVycyBkZXBlbmRpbmcgb24gdGhlIGhhc2h0eXBlXG4gKiBAcGFyYW0gaGFzaFR5cGVcbiAqIEByZXR1cm5zIGRvdWJsZSBTSEEtMjU2LCAyNTYtYml0IEJMQUtFMmIgaGFzaCBvciAyNTYtYml0IHplcm8gaWYgZG9lc24ndCBhcHBseVxuICovXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuZ2V0U2VxdWVuY2VIYXNoID0gZnVuY3Rpb24gKGhhc2hUeXBlKSB7XG4gIGlmICghKGhhc2hUeXBlICYgVHJhbnNhY3Rpb24uU0lHSEFTSF9BTllPTkVDQU5QQVkpICYmXG4gICAgKGhhc2hUeXBlICYgMHgxZikgIT09IFRyYW5zYWN0aW9uLlNJR0hBU0hfU0lOR0xFICYmXG4gICAgKGhhc2hUeXBlICYgMHgxZikgIT09IFRyYW5zYWN0aW9uLlNJR0hBU0hfTk9ORSkge1xuICAgIHZhciBidWZmZXJXcml0ZXIgPSBuZXcgQnVmZmVyV3JpdGVyKEJ1ZmZlci5hbGxvY1Vuc2FmZSg0ICogdGhpcy5pbnMubGVuZ3RoKSlcblxuICAgIHRoaXMuaW5zLmZvckVhY2goZnVuY3Rpb24gKHR4SW4pIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0eEluLnNlcXVlbmNlKVxuICAgIH0pXG5cbiAgICBpZiAoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspKSB7XG4gICAgICByZXR1cm4gdGhpcy5nZXRCbGFrZTJiSGFzaChidWZmZXJXcml0ZXIuYnVmZmVyLCAnWmNhc2hTZXF1ZW5jSGFzaCcpXG4gICAgfVxuICAgIHJldHVybiBiY3J5cHRvLmhhc2gyNTYoYnVmZmVyV3JpdGVyLmJ1ZmZlcilcbiAgfVxuICByZXR1cm4gWkVST1xufVxuXG4vKipcbiAqIEJ1aWxkIGEgaGFzaCBmb3Igb25lLCBhbGwgb3Igbm9uZSBvZiB0aGUgdHJhbnNhY3Rpb24gb3V0cHV0cyBkZXBlbmRpbmcgb24gdGhlIGhhc2h0eXBlXG4gKiBAcGFyYW0gaGFzaFR5cGVcbiAqIEBwYXJhbSBpbkluZGV4XG4gKiBAcmV0dXJucyBkb3VibGUgU0hBLTI1NiwgMjU2LWJpdCBCTEFLRTJiIGhhc2ggb3IgMjU2LWJpdCB6ZXJvIGlmIGRvZXNuJ3QgYXBwbHlcbiAqL1xuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmdldE91dHB1dHNIYXNoID0gZnVuY3Rpb24gKGhhc2hUeXBlLCBpbkluZGV4KSB7XG4gIHZhciBidWZmZXJXcml0ZXJcbiAgaWYgKChoYXNoVHlwZSAmIDB4MWYpICE9PSBUcmFuc2FjdGlvbi5TSUdIQVNIX1NJTkdMRSAmJiAoaGFzaFR5cGUgJiAweDFmKSAhPT0gVHJhbnNhY3Rpb24uU0lHSEFTSF9OT05FKSB7XG4gICAgLy8gRmluZCBvdXQgdGhlIHNpemUgb2YgdGhlIG91dHB1dHMgYW5kIHdyaXRlIHRoZW1cbiAgICB2YXIgdHhPdXRzU2l6ZSA9IHRoaXMub3V0cy5yZWR1Y2UoZnVuY3Rpb24gKHN1bSwgb3V0cHV0KSB7XG4gICAgICByZXR1cm4gc3VtICsgOCArIHZhclNsaWNlU2l6ZShvdXRwdXQuc2NyaXB0KVxuICAgIH0sIDApXG5cbiAgICBidWZmZXJXcml0ZXIgPSBuZXcgQnVmZmVyV3JpdGVyKEJ1ZmZlci5hbGxvY1Vuc2FmZSh0eE91dHNTaXplKSlcblxuICAgIHRoaXMub3V0cy5mb3JFYWNoKGZ1bmN0aW9uIChvdXQpIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQ2NChvdXQudmFsdWUpXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVWYXJTbGljZShvdXQuc2NyaXB0KVxuICAgIH0pXG5cbiAgICBpZiAoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspKSB7XG4gICAgICByZXR1cm4gdGhpcy5nZXRCbGFrZTJiSGFzaChidWZmZXJXcml0ZXIuYnVmZmVyLCAnWmNhc2hPdXRwdXRzSGFzaCcpXG4gICAgfVxuICAgIHJldHVybiBiY3J5cHRvLmhhc2gyNTYoYnVmZmVyV3JpdGVyLmJ1ZmZlcilcbiAgfSBlbHNlIGlmICgoaGFzaFR5cGUgJiAweDFmKSA9PT0gVHJhbnNhY3Rpb24uU0lHSEFTSF9TSU5HTEUgJiYgaW5JbmRleCA8IHRoaXMub3V0cy5sZW5ndGgpIHtcbiAgICAvLyBXcml0ZSBvbmx5IHRoZSBvdXRwdXQgc3BlY2lmaWVkIGluIGluSW5kZXhcbiAgICB2YXIgb3V0cHV0ID0gdGhpcy5vdXRzW2luSW5kZXhdXG5cbiAgICBidWZmZXJXcml0ZXIgPSBuZXcgQnVmZmVyV3JpdGVyKEJ1ZmZlci5hbGxvY1Vuc2FmZSg4ICsgdmFyU2xpY2VTaXplKG91dHB1dC5zY3JpcHQpKSlcbiAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50NjQob3V0cHV0LnZhbHVlKVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZhclNsaWNlKG91dHB1dC5zY3JpcHQpXG5cbiAgICBpZiAoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspKSB7XG4gICAgICByZXR1cm4gdGhpcy5nZXRCbGFrZTJiSGFzaChidWZmZXJXcml0ZXIuYnVmZmVyLCAnWmNhc2hPdXRwdXRzSGFzaCcpXG4gICAgfVxuICAgIHJldHVybiBiY3J5cHRvLmhhc2gyNTYoYnVmZmVyV3JpdGVyLmJ1ZmZlcilcbiAgfVxuICByZXR1cm4gWkVST1xufVxuXG4vKipcbiAqIEhhc2ggdHJhbnNhY3Rpb24gZm9yIHNpZ25pbmcgYSB0cmFuc3BhcmVudCB0cmFuc2FjdGlvbiBpbiBaY2FzaC4gUHJvdGVjdGVkIHRyYW5zYWN0aW9ucyBhcmUgbm90IHN1cHBvcnRlZC5cbiAqIEBwYXJhbSBpbkluZGV4XG4gKiBAcGFyYW0gcHJldk91dFNjcmlwdFxuICogQHBhcmFtIHZhbHVlXG4gKiBAcGFyYW0gaGFzaFR5cGVcbiAqIEByZXR1cm5zIGRvdWJsZSBTSEEtMjU2IG9yIDI1Ni1iaXQgQkxBS0UyYiBoYXNoXG4gKi9cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5oYXNoRm9yWmNhc2hTaWduYXR1cmUgPSBmdW5jdGlvbiAoaW5JbmRleCwgcHJldk91dFNjcmlwdCwgdmFsdWUsIGhhc2hUeXBlKSB7XG4gIHR5cGVmb3JjZSh0eXBlcy50dXBsZSh0eXBlcy5VSW50MzIsIHR5cGVzLkJ1ZmZlciwgdHlwZXMuU2F0b3NoaSwgdHlwZXMuVUludDMyKSwgYXJndW1lbnRzKVxuICBpZiAoIWNvaW5zLmlzWmNhc2godGhpcy5uZXR3b3JrKSkge1xuICAgIHRocm93IG5ldyBFcnJvcignaGFzaEZvclpjYXNoU2lnbmF0dXJlIGNhbiBvbmx5IGJlIGNhbGxlZCB3aGVuIHVzaW5nIFpjYXNoIG5ldHdvcmsnKVxuICB9XG4gIGlmICh0aGlzLmpvaW5zcGxpdHMubGVuZ3RoID4gMCkge1xuICAgIHRocm93IG5ldyBFcnJvcignSGFzaCBzaWduYXR1cmUgZm9yIFpjYXNoIHByb3RlY3RlZCB0cmFuc2FjdGlvbnMgaXMgbm90IHN1cHBvcnRlZCcpXG4gIH1cblxuICBpZiAoaW5JbmRleCA+PSB0aGlzLmlucy5sZW5ndGggJiYgaW5JbmRleCAhPT0gVkFMVUVfVUlOVDY0X01BWCkge1xuICAgIHRocm93IG5ldyBFcnJvcignSW5wdXQgaW5kZXggaXMgb3V0IG9mIHJhbmdlJylcbiAgfVxuXG4gIGlmICh0aGlzLmlzT3ZlcndpbnRlckNvbXBhdGlibGUoKSkge1xuICAgIHZhciBoYXNoUHJldm91dHMgPSB0aGlzLmdldFByZXZvdXRIYXNoKGhhc2hUeXBlKVxuICAgIHZhciBoYXNoU2VxdWVuY2UgPSB0aGlzLmdldFNlcXVlbmNlSGFzaChoYXNoVHlwZSlcbiAgICB2YXIgaGFzaE91dHB1dHMgPSB0aGlzLmdldE91dHB1dHNIYXNoKGhhc2hUeXBlLCBpbkluZGV4KVxuICAgIHZhciBoYXNoSm9pblNwbGl0cyA9IFpFUk9cbiAgICB2YXIgaGFzaFNoaWVsZGVkU3BlbmRzID0gWkVST1xuICAgIHZhciBoYXNoU2hpZWxkZWRPdXRwdXRzID0gWkVST1xuXG4gICAgdmFyIGJ1ZmZlcldyaXRlclxuICAgIHZhciBiYXNlQnVmZmVyU2l6ZSA9IDBcbiAgICBiYXNlQnVmZmVyU2l6ZSArPSA0ICogNSAgLy8gaGVhZGVyLCBuVmVyc2lvbkdyb3VwSWQsIGxvY2tfdGltZSwgbkV4cGlyeUhlaWdodCwgaGFzaFR5cGVcbiAgICBiYXNlQnVmZmVyU2l6ZSArPSAzMiAqIDQgIC8vIDI1NiBoYXNoZXM6IGhhc2hQcmV2b3V0cywgaGFzaFNlcXVlbmNlLCBoYXNoT3V0cHV0cywgaGFzaEpvaW5TcGxpdHNcbiAgICBpZiAoaW5JbmRleCAhPT0gVkFMVUVfVUlOVDY0X01BWCkge1xuICAgICAgLy8gSWYgdGhpcyBoYXNoIGlzIGZvciBhIHRyYW5zcGFyZW50IGlucHV0IHNpZ25hdHVyZSAoaS5lLiBub3QgZm9yIHR4VG8uam9pblNwbGl0U2lnKSwgd2UgbmVlZCBleHRyYSBzcGFjZVxuICAgICAgYmFzZUJ1ZmZlclNpemUgKz0gNCAqIDIgIC8vIGlucHV0LmluZGV4LCBpbnB1dC5zZXF1ZW5jZVxuICAgICAgYmFzZUJ1ZmZlclNpemUgKz0gOCAgLy8gdmFsdWVcbiAgICAgIGJhc2VCdWZmZXJTaXplICs9IDMyICAvLyBpbnB1dC5oYXNoXG4gICAgICBiYXNlQnVmZmVyU2l6ZSArPSB2YXJTbGljZVNpemUocHJldk91dFNjcmlwdCkgIC8vIHByZXZPdXRTY3JpcHRcbiAgICB9XG4gICAgaWYgKHRoaXMuaXNTYXBsaW5nQ29tcGF0aWJsZSgpKSB7XG4gICAgICBiYXNlQnVmZmVyU2l6ZSArPSAzMiAqIDIgIC8vIGhhc2hTaGllbGRlZFNwZW5kcyBhbmQgaGFzaFNoaWVsZGVkT3V0cHV0c1xuICAgICAgYmFzZUJ1ZmZlclNpemUgKz0gOCAgLy8gdmFsdWVCYWxhbmNlXG4gICAgfVxuICAgIGJ1ZmZlcldyaXRlciA9IG5ldyBCdWZmZXJXcml0ZXIoQnVmZmVyLmFsbG9jKGJhc2VCdWZmZXJTaXplKSlcblxuICAgIGJ1ZmZlcldyaXRlci53cml0ZUludDMyKHRoaXMuZ2V0SGVhZGVyKCkpXG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHRoaXMudmVyc2lvbkdyb3VwSWQpXG4gICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UoaGFzaFByZXZvdXRzKVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKGhhc2hTZXF1ZW5jZSlcbiAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShoYXNoT3V0cHV0cylcbiAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShoYXNoSm9pblNwbGl0cylcbiAgICBpZiAodGhpcy5pc1NhcGxpbmdDb21wYXRpYmxlKCkpIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKGhhc2hTaGllbGRlZFNwZW5kcylcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKGhhc2hTaGllbGRlZE91dHB1dHMpXG4gICAgfVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0aGlzLmxvY2t0aW1lKVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0aGlzLmV4cGlyeUhlaWdodClcbiAgICBpZiAodGhpcy5pc1NhcGxpbmdDb21wYXRpYmxlKCkpIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQ2NCh0aGlzLnZhbHVlQmFsYW5jZSlcbiAgICB9XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKGhhc2hUeXBlKVxuXG4gICAgLy8gSWYgdGhpcyBoYXNoIGlzIGZvciBhIHRyYW5zcGFyZW50IGlucHV0IHNpZ25hdHVyZSAoaS5lLiBub3QgZm9yIHR4VG8uam9pblNwbGl0U2lnKTpcbiAgICBpZiAoaW5JbmRleCAhPT0gVkFMVUVfVUlOVDY0X01BWCkge1xuICAgICAgLy8gVGhlIGlucHV0IGJlaW5nIHNpZ25lZCAocmVwbGFjaW5nIHRoZSBzY3JpcHRTaWcgd2l0aCBzY3JpcHRDb2RlICsgYW1vdW50KVxuICAgICAgLy8gVGhlIHByZXZvdXQgbWF5IGFscmVhZHkgYmUgY29udGFpbmVkIGluIGhhc2hQcmV2b3V0LCBhbmQgdGhlIG5TZXF1ZW5jZVxuICAgICAgLy8gbWF5IGFscmVhZHkgYmUgY29udGFpbmVkIGluIGhhc2hTZXF1ZW5jZS5cbiAgICAgIHZhciBpbnB1dCA9IHRoaXMuaW5zW2luSW5kZXhdXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShpbnB1dC5oYXNoKVxuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKGlucHV0LmluZGV4KVxuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlVmFyU2xpY2UocHJldk91dFNjcmlwdClcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQ2NCh2YWx1ZSlcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMihpbnB1dC5zZXF1ZW5jZSlcbiAgICB9XG5cbiAgICB2YXIgcGVyc29uYWxpemF0aW9uID0gQnVmZmVyLmFsbG9jKDE2KVxuICAgIHZhciBwcmVmaXggPSAnWmNhc2hTaWdIYXNoJ1xuICAgIHBlcnNvbmFsaXphdGlvbi53cml0ZShwcmVmaXgpXG4gICAgcGVyc29uYWxpemF0aW9uLndyaXRlVUludDMyTEUodGhpcy5jb25zZW5zdXNCcmFuY2hJZCwgcHJlZml4Lmxlbmd0aClcblxuICAgIHJldHVybiB0aGlzLmdldEJsYWtlMmJIYXNoKGJ1ZmZlcldyaXRlci5idWZmZXIsIHBlcnNvbmFsaXphdGlvbilcbiAgfVxuICAvLyBUT0RPOiBzdXBwb3J0IG5vbiBvdmVyd2ludGVyIHRyYW5zYWN0aW9uc1xufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuaGFzaEZvcldpdG5lc3NWMCA9IGZ1bmN0aW9uIChpbkluZGV4LCBwcmV2T3V0U2NyaXB0LCB2YWx1ZSwgaGFzaFR5cGUpIHtcbiAgdHlwZWZvcmNlKHR5cGVzLnR1cGxlKHR5cGVzLlVJbnQzMiwgdHlwZXMuQnVmZmVyLCB0eXBlcy5TYXRvc2hpLCB0eXBlcy5VSW50MzIpLCBhcmd1bWVudHMpXG5cbiAgdmFyIGhhc2hQcmV2b3V0cyA9IHRoaXMuZ2V0UHJldm91dEhhc2goaGFzaFR5cGUpXG4gIHZhciBoYXNoU2VxdWVuY2UgPSB0aGlzLmdldFNlcXVlbmNlSGFzaChoYXNoVHlwZSlcbiAgdmFyIGhhc2hPdXRwdXRzID0gdGhpcy5nZXRPdXRwdXRzSGFzaChoYXNoVHlwZSwgaW5JbmRleClcblxuICB2YXIgYnVmZmVyV3JpdGVyID0gbmV3IEJ1ZmZlcldyaXRlcihCdWZmZXIuYWxsb2NVbnNhZmUoMTU2ICsgdmFyU2xpY2VTaXplKHByZXZPdXRTY3JpcHQpKSlcbiAgdmFyIGlucHV0ID0gdGhpcy5pbnNbaW5JbmRleF1cbiAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHRoaXMudmVyc2lvbilcbiAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UoaGFzaFByZXZvdXRzKVxuICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShoYXNoU2VxdWVuY2UpXG4gIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKGlucHV0Lmhhc2gpXG4gIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMihpbnB1dC5pbmRleClcbiAgYnVmZmVyV3JpdGVyLndyaXRlVmFyU2xpY2UocHJldk91dFNjcmlwdClcbiAgYnVmZmVyV3JpdGVyLndyaXRlVUludDY0KHZhbHVlKVxuICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIoaW5wdXQuc2VxdWVuY2UpXG4gIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKGhhc2hPdXRwdXRzKVxuICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodGhpcy5sb2NrdGltZSlcbiAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKGhhc2hUeXBlKVxuICByZXR1cm4gYmNyeXB0by5oYXNoMjU2KGJ1ZmZlcldyaXRlci5idWZmZXIpXG59XG5cbi8qKlxuICogSGFzaCB0cmFuc2FjdGlvbiBmb3Igc2lnbmluZyBhIHNwZWNpZmljIGlucHV0IGZvciBCaXRjb2luIENhc2guXG4gKi9cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5oYXNoRm9yQ2FzaFNpZ25hdHVyZSA9IGZ1bmN0aW9uIChpbkluZGV4LCBwcmV2T3V0U2NyaXB0LCBpbkFtb3VudCwgaGFzaFR5cGUpIHtcbiAgdHlwZWZvcmNlKHR5cGVzLnR1cGxlKHR5cGVzLlVJbnQzMiwgdHlwZXMuQnVmZmVyLCAvKiB0eXBlcy5VSW50OCAqLyB0eXBlcy5OdW1iZXIsIHR5cGVzLm1heWJlKHR5cGVzLlVJbnQ1MykpLCBhcmd1bWVudHMpXG5cbiAgLy8gVGhpcyBmdW5jdGlvbiB3b3JrcyB0aGUgd2F5IGl0IGRvZXMgYmVjYXVzZSBCaXRjb2luIENhc2hcbiAgLy8gdXNlcyBCSVAxNDMgYXMgdGhlaXIgcmVwbGF5IHByb3RlY3Rpb24sIEFORCB0aGVpciBhbGdvXG4gIC8vIGluY2x1ZGVzIGBmb3JrSWQgfCBoYXNoVHlwZWAsIEFORCBzaW5jZSB0aGVpciBmb3JrSWQ9MCxcbiAgLy8gdGhpcyBpcyBhIE5PUCwgYW5kIGhhcyBubyBkaWZmZXJlbmNlIHRvIHNlZ3dpdC4gVG8gc3VwcG9ydFxuICAvLyBvdGhlciBmb3JrcywgYW5vdGhlciBwYXJhbWV0ZXIgaXMgcmVxdWlyZWQsIGFuZCBhIG5ldyBwYXJhbWV0ZXJcbiAgLy8gd291bGQgYmUgcmVxdWlyZWQgaW4gdGhlIGhhc2hGb3JXaXRuZXNzVjAgZnVuY3Rpb24sIG9yXG4gIC8vIGl0IGNvdWxkIGJlIGJyb2tlbiBpbnRvIHR3by4uXG5cbiAgLy8gQklQMTQzIHNpZ2hhc2ggYWN0aXZhdGVkIGluIEJpdGNvaW5DYXNoIHZpYSAweDQwIGJpdFxuICBpZiAoaGFzaFR5cGUgJiBUcmFuc2FjdGlvbi5TSUdIQVNIX0JJVENPSU5DQVNIQklQMTQzKSB7XG4gICAgaWYgKHR5cGVzLk51bGwoaW5BbW91bnQpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0JpdGNvaW4gQ2FzaCBzaWdoYXNoIHJlcXVpcmVzIHZhbHVlIG9mIGlucHV0IHRvIGJlIHNpZ25lZC4nKVxuICAgIH1cbiAgICByZXR1cm4gdGhpcy5oYXNoRm9yV2l0bmVzc1YwKGluSW5kZXgsIHByZXZPdXRTY3JpcHQsIGluQW1vdW50LCBoYXNoVHlwZSlcbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gdGhpcy5oYXNoRm9yU2lnbmF0dXJlKGluSW5kZXgsIHByZXZPdXRTY3JpcHQsIGhhc2hUeXBlKVxuICB9XG59XG5cbi8qKlxuICogSGFzaCB0cmFuc2FjdGlvbiBmb3Igc2lnbmluZyBhIHNwZWNpZmljIGlucHV0IGZvciBCaXRjb2luIEdvbGQuXG4gKi9cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5oYXNoRm9yR29sZFNpZ25hdHVyZSA9IGZ1bmN0aW9uIChpbkluZGV4LCBwcmV2T3V0U2NyaXB0LCBpbkFtb3VudCwgaGFzaFR5cGUsIHNpZ1ZlcnNpb24pIHtcbiAgdHlwZWZvcmNlKHR5cGVzLnR1cGxlKHR5cGVzLlVJbnQzMiwgdHlwZXMuQnVmZmVyLCAvKiB0eXBlcy5VSW50OCAqLyB0eXBlcy5OdW1iZXIsIHR5cGVzLm1heWJlKHR5cGVzLlVJbnQ1MykpLCBhcmd1bWVudHMpXG5cbiAgLy8gQml0Y29pbiBHb2xkIGFsc28gaW1wbGVtZW50cyBzZWdyZWdhdGVkIHdpdG5lc3NcbiAgLy8gdGhlcmVmb3JlIHdlIGNhbiBwdWxsIG91dCB0aGUgc2V0dGluZyBvZiBuRm9ya0hhc2hUeXBlXG4gIC8vIGFuZCBwYXNzIGl0IGludG8gdGhlIGZ1bmN0aW9ucy5cblxuICB2YXIgbkZvcmtIYXNoVHlwZSA9IGhhc2hUeXBlXG4gIHZhciBmVXNlRm9ya0lkID0gKGhhc2hUeXBlICYgVHJhbnNhY3Rpb24uU0lHSEFTSF9CSVRDT0lOQ0FTSEJJUDE0MykgPiAwXG4gIGlmIChmVXNlRm9ya0lkKSB7XG4gICAgbkZvcmtIYXNoVHlwZSB8PSB0aGlzLm5ldHdvcmsuZm9ya0lkIDw8IDhcbiAgfVxuXG4gIC8vIEJJUDE0MyBzaWdoYXNoIGFjdGl2YXRlZCBpbiBCaXRjb2luQ2FzaCB2aWEgMHg0MCBiaXRcbiAgaWYgKHNpZ1ZlcnNpb24gfHwgZlVzZUZvcmtJZCkge1xuICAgIGlmICh0eXBlcy5OdWxsKGluQW1vdW50KSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdCaXRjb2luIENhc2ggc2lnaGFzaCByZXF1aXJlcyB2YWx1ZSBvZiBpbnB1dCB0byBiZSBzaWduZWQuJylcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuaGFzaEZvcldpdG5lc3NWMChpbkluZGV4LCBwcmV2T3V0U2NyaXB0LCBpbkFtb3VudCwgbkZvcmtIYXNoVHlwZSlcbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gdGhpcy5oYXNoRm9yU2lnbmF0dXJlKGluSW5kZXgsIHByZXZPdXRTY3JpcHQsIG5Gb3JrSGFzaFR5cGUpXG4gIH1cbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLmdldEhhc2ggPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiBiY3J5cHRvLmhhc2gyNTYodGhpcy5fX3RvQnVmZmVyKHVuZGVmaW5lZCwgdW5kZWZpbmVkLCBmYWxzZSkpXG59XG5cblRyYW5zYWN0aW9uLnByb3RvdHlwZS5nZXRJZCA9IGZ1bmN0aW9uICgpIHtcbiAgLy8gdHJhbnNhY3Rpb24gaGFzaCdzIGFyZSBkaXNwbGF5ZWQgaW4gcmV2ZXJzZSBvcmRlclxuICByZXR1cm4gdGhpcy5nZXRIYXNoKCkucmV2ZXJzZSgpLnRvU3RyaW5nKCdoZXgnKVxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUudG9CdWZmZXIgPSBmdW5jdGlvbiAoYnVmZmVyLCBpbml0aWFsT2Zmc2V0KSB7XG4gIHJldHVybiB0aGlzLl9fdG9CdWZmZXIoYnVmZmVyLCBpbml0aWFsT2Zmc2V0LCB0cnVlKVxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuX190b0J1ZmZlciA9IGZ1bmN0aW9uIChidWZmZXIsIGluaXRpYWxPZmZzZXQsIF9fYWxsb3dXaXRuZXNzKSB7XG4gIGlmICghYnVmZmVyKSBidWZmZXIgPSBCdWZmZXIuYWxsb2NVbnNhZmUodGhpcy5fX2J5dGVMZW5ndGgoX19hbGxvd1dpdG5lc3MpKVxuXG4gIGNvbnN0IGJ1ZmZlcldyaXRlciA9IGNvaW5zLmlzWmNhc2godGhpcy5uZXR3b3JrKVxuICAgID8gbmV3IFpjYXNoQnVmZmVyV3JpdGVyKGJ1ZmZlciwgaW5pdGlhbE9mZnNldCB8fCAwKVxuICAgIDogbmV3IEJ1ZmZlcldyaXRlcihidWZmZXIsIGluaXRpYWxPZmZzZXQgfHwgMClcblxuICBmdW5jdGlvbiB3cml0ZVVJbnQxNiAoaSkge1xuICAgIGJ1ZmZlcldyaXRlci5vZmZzZXQgPSBidWZmZXJXcml0ZXIuYnVmZmVyLndyaXRlVUludDE2TEUoaSwgYnVmZmVyV3JpdGVyLm9mZnNldClcbiAgfVxuXG4gIGlmICh0aGlzLmlzT3ZlcndpbnRlckNvbXBhdGlibGUoKSkge1xuICAgIHZhciBtYXNrID0gKHRoaXMub3ZlcndpbnRlcmVkID8gMSA6IDApXG4gICAgYnVmZmVyV3JpdGVyLndyaXRlSW50MzIodGhpcy52ZXJzaW9uIHwgKG1hc2sgPDwgMzEpKSAgLy8gU2V0IG92ZXJ3aW50ZXIgYml0XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHRoaXMudmVyc2lvbkdyb3VwSWQpXG4gIH0gZWxzZSBpZiAodGhpcy5pc0Rhc2hTcGVjaWFsVHJhbnNhY3Rpb24oKSkge1xuICAgIHdyaXRlVUludDE2KHRoaXMudmVyc2lvbilcbiAgICB3cml0ZVVJbnQxNih0aGlzLnR5cGUpXG4gIH0gZWxzZSB7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlSW50MzIodGhpcy52ZXJzaW9uKVxuICB9XG5cbiAgdmFyIGhhc1dpdG5lc3NlcyA9IF9fYWxsb3dXaXRuZXNzICYmIHRoaXMuaGFzV2l0bmVzc2VzKClcblxuICBpZiAoaGFzV2l0bmVzc2VzKSB7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDgoVHJhbnNhY3Rpb24uQURWQU5DRURfVFJBTlNBQ1RJT05fTUFSS0VSKVxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQ4KFRyYW5zYWN0aW9uLkFEVkFOQ0VEX1RSQU5TQUNUSU9OX0ZMQUcpXG4gIH1cblxuICBidWZmZXJXcml0ZXIud3JpdGVWYXJJbnQodGhpcy5pbnMubGVuZ3RoKVxuXG4gIHRoaXMuaW5zLmZvckVhY2goZnVuY3Rpb24gKHR4SW4pIHtcbiAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZSh0eEluLmhhc2gpXG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHR4SW4uaW5kZXgpXG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVmFyU2xpY2UodHhJbi5zY3JpcHQpXG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHR4SW4uc2VxdWVuY2UpXG4gIH0pXG5cbiAgYnVmZmVyV3JpdGVyLndyaXRlVmFySW50KHRoaXMub3V0cy5sZW5ndGgpXG4gIHRoaXMub3V0cy5mb3JFYWNoKGZ1bmN0aW9uICh0eE91dCkge1xuICAgIGlmICghdHhPdXQudmFsdWVCdWZmZXIpIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQ2NCh0eE91dC52YWx1ZSlcbiAgICB9IGVsc2Uge1xuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UodHhPdXQudmFsdWVCdWZmZXIpXG4gICAgfVxuXG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVmFyU2xpY2UodHhPdXQuc2NyaXB0KVxuICB9KVxuXG4gIGlmIChoYXNXaXRuZXNzZXMpIHtcbiAgICB0aGlzLmlucy5mb3JFYWNoKGZ1bmN0aW9uIChpbnB1dCkge1xuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlVmVjdG9yKGlucHV0LndpdG5lc3MpXG4gICAgfSlcbiAgfVxuXG4gIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0aGlzLmxvY2t0aW1lKVxuXG4gIGlmICh0aGlzLmlzT3ZlcndpbnRlckNvbXBhdGlibGUoKSkge1xuICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQzMih0aGlzLmV4cGlyeUhlaWdodClcbiAgfVxuXG4gIGlmICh0aGlzLmlzU2FwbGluZ0NvbXBhdGlibGUoKSkge1xuICAgIGJ1ZmZlcldyaXRlci53cml0ZVVJbnQ2NCh0aGlzLnZhbHVlQmFsYW5jZSlcblxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZhckludCh0aGlzLnZTaGllbGRlZFNwZW5kLmxlbmd0aClcbiAgICB0aGlzLnZTaGllbGRlZFNwZW5kLmZvckVhY2goZnVuY3Rpb24gKHNoaWVsZGVkU3BlbmQpIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKHNoaWVsZGVkU3BlbmQuY3YpXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShzaGllbGRlZFNwZW5kLmFuY2hvcilcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKHNoaWVsZGVkU3BlbmQubnVsbGlmaWVyKVxuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2Uoc2hpZWxkZWRTcGVuZC5yaylcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKHNoaWVsZGVkU3BlbmQuemtwcm9vZi5zQSlcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKHNoaWVsZGVkU3BlbmQuemtwcm9vZi5zQilcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKHNoaWVsZGVkU3BlbmQuemtwcm9vZi5zQylcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKHNoaWVsZGVkU3BlbmQuc3BlbmRBdXRoU2lnKVxuICAgIH0pXG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVmFySW50KHRoaXMudlNoaWVsZGVkT3V0cHV0Lmxlbmd0aClcbiAgICB0aGlzLnZTaGllbGRlZE91dHB1dC5mb3JFYWNoKGZ1bmN0aW9uIChzaGllbGRlZE91dHB1dCkge1xuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2Uoc2hpZWxkZWRPdXRwdXQuY3YpXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShzaGllbGRlZE91dHB1dC5jbXUpXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShzaGllbGRlZE91dHB1dC5lcGhlbWVyYWxLZXkpXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShzaGllbGRlZE91dHB1dC5lbmNDaXBoZXJ0ZXh0KVxuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2Uoc2hpZWxkZWRPdXRwdXQub3V0Q2lwaGVydGV4dClcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKHNoaWVsZGVkT3V0cHV0LnprcHJvb2Yuc0EpXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShzaGllbGRlZE91dHB1dC56a3Byb29mLnNCKVxuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2Uoc2hpZWxkZWRPdXRwdXQuemtwcm9vZi5zQylcbiAgICB9KVxuICB9XG5cbiAgaWYgKHRoaXMuc3VwcG9ydHNKb2luU3BsaXRzKCkpIHtcbiAgICBidWZmZXJXcml0ZXIud3JpdGVWYXJJbnQodGhpcy5qb2luc3BsaXRzLmxlbmd0aClcbiAgICB0aGlzLmpvaW5zcGxpdHMuZm9yRWFjaChmdW5jdGlvbiAoam9pbnNwbGl0KSB7XG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50NjQoam9pbnNwbGl0LnZwdWJPbGQpXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50NjQoam9pbnNwbGl0LnZwdWJOZXcpXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShqb2luc3BsaXQuYW5jaG9yKVxuICAgICAgam9pbnNwbGl0Lm51bGxpZmllcnMuZm9yRWFjaChmdW5jdGlvbiAobnVsbGlmaWVyKSB7XG4gICAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKG51bGxpZmllcilcbiAgICAgIH0pXG4gICAgICBqb2luc3BsaXQuY29tbWl0bWVudHMuZm9yRWFjaChmdW5jdGlvbiAobnVsbGlmaWVyKSB7XG4gICAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKG51bGxpZmllcilcbiAgICAgIH0pXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShqb2luc3BsaXQuZXBoZW1lcmFsS2V5KVxuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2Uoam9pbnNwbGl0LnJhbmRvbVNlZWQpXG4gICAgICBqb2luc3BsaXQubWFjcy5mb3JFYWNoKGZ1bmN0aW9uIChudWxsaWZpZXIpIHtcbiAgICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UobnVsbGlmaWVyKVxuICAgICAgfSlcbiAgICAgIGlmICh0aGlzLmlzU2FwbGluZ0NvbXBhdGlibGUoKSkge1xuICAgICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShqb2luc3BsaXQuemtwcm9vZi5zQSlcbiAgICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2Uoam9pbnNwbGl0LnprcHJvb2Yuc0IpXG4gICAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKGpvaW5zcGxpdC56a3Byb29mLnNDKVxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgYnVmZmVyV3JpdGVyLndyaXRlQ29tcHJlc3NlZEcxKGpvaW5zcGxpdC56a3Byb29mLmdBKVxuICAgICAgICBidWZmZXJXcml0ZXIud3JpdGVDb21wcmVzc2VkRzEoam9pbnNwbGl0LnprcHJvb2YuZ0FQcmltZSlcbiAgICAgICAgYnVmZmVyV3JpdGVyLndyaXRlQ29tcHJlc3NlZEcyKGpvaW5zcGxpdC56a3Byb29mLmdCKVxuICAgICAgICBidWZmZXJXcml0ZXIud3JpdGVDb21wcmVzc2VkRzEoam9pbnNwbGl0LnprcHJvb2YuZ0JQcmltZSlcbiAgICAgICAgYnVmZmVyV3JpdGVyLndyaXRlQ29tcHJlc3NlZEcxKGpvaW5zcGxpdC56a3Byb29mLmdDKVxuICAgICAgICBidWZmZXJXcml0ZXIud3JpdGVDb21wcmVzc2VkRzEoam9pbnNwbGl0LnprcHJvb2YuZ0NQcmltZSlcbiAgICAgICAgYnVmZmVyV3JpdGVyLndyaXRlQ29tcHJlc3NlZEcxKGpvaW5zcGxpdC56a3Byb29mLmdLKVxuICAgICAgICBidWZmZXJXcml0ZXIud3JpdGVDb21wcmVzc2VkRzEoam9pbnNwbGl0LnprcHJvb2YuZ0gpXG4gICAgICB9XG4gICAgICBqb2luc3BsaXQuY2lwaGVydGV4dHMuZm9yRWFjaChmdW5jdGlvbiAoY2lwaGVydGV4dCkge1xuICAgICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZShjaXBoZXJ0ZXh0KVxuICAgICAgfSlcbiAgICB9LCB0aGlzKVxuICAgIGlmICh0aGlzLmpvaW5zcGxpdHMubGVuZ3RoID4gMCkge1xuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UodGhpcy5qb2luc3BsaXRQdWJrZXkpXG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVTbGljZSh0aGlzLmpvaW5zcGxpdFNpZylcbiAgICB9XG4gIH1cblxuICBpZiAodGhpcy5pc1NhcGxpbmdDb21wYXRpYmxlKCkgJiYgdGhpcy52U2hpZWxkZWRTcGVuZC5sZW5ndGggKyB0aGlzLnZTaGllbGRlZE91dHB1dC5sZW5ndGggPiAwKSB7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UodGhpcy5iaW5kaW5nU2lnKVxuICB9XG5cbiAgaWYgKHRoaXMuaXNEYXNoU3BlY2lhbFRyYW5zYWN0aW9uKCkpIHtcbiAgICBidWZmZXJXcml0ZXIud3JpdGVWYXJTbGljZSh0aGlzLmV4dHJhUGF5bG9hZClcbiAgfVxuXG4gIGlmIChpbml0aWFsT2Zmc2V0ICE9PSB1bmRlZmluZWQpIHJldHVybiBidWZmZXIuc2xpY2UoaW5pdGlhbE9mZnNldCwgYnVmZmVyV3JpdGVyLm9mZnNldClcbiAgLy8gYXZvaWQgc2xpY2luZyB1bmxlc3MgbmVjZXNzYXJ5XG4gIC8vIFRPRE8gKGh0dHBzOi8vZ2l0aHViLmNvbS9CaXRHby9iaXRnby11dHhvLWxpYi9pc3N1ZXMvMTEpOiB3ZSBzaG91bGRuJ3QgaGF2ZSB0byBzbGljZSB0aGUgZmluYWwgYnVmZmVyXG4gIHJldHVybiBidWZmZXIuc2xpY2UoMCwgYnVmZmVyV3JpdGVyLm9mZnNldClcbn1cblxuVHJhbnNhY3Rpb24ucHJvdG90eXBlLnRvSGV4ID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gdGhpcy50b0J1ZmZlcigpLnRvU3RyaW5nKCdoZXgnKVxufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuc2V0SW5wdXRTY3JpcHQgPSBmdW5jdGlvbiAoaW5kZXgsIHNjcmlwdFNpZykge1xuICB0eXBlZm9yY2UodHlwZXMudHVwbGUodHlwZXMuTnVtYmVyLCB0eXBlcy5CdWZmZXIpLCBhcmd1bWVudHMpXG5cbiAgdGhpcy5pbnNbaW5kZXhdLnNjcmlwdCA9IHNjcmlwdFNpZ1xufVxuXG5UcmFuc2FjdGlvbi5wcm90b3R5cGUuc2V0V2l0bmVzcyA9IGZ1bmN0aW9uIChpbmRleCwgd2l0bmVzcykge1xuICB0eXBlZm9yY2UodHlwZXMudHVwbGUodHlwZXMuTnVtYmVyLCBbdHlwZXMuQnVmZmVyXSksIGFyZ3VtZW50cylcblxuICB0aGlzLmluc1tpbmRleF0ud2l0bmVzcyA9IHdpdG5lc3Ncbn1cblxubW9kdWxlLmV4cG9ydHMgPSBUcmFuc2FjdGlvblxuIl19