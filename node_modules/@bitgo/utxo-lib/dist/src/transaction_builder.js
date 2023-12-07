var Buffer = require('safe-buffer').Buffer;
var baddress = require('./address');
var bcrypto = require('./crypto');
var bscript = require('./script');
var btemplates = require('./templates');
var coins = require('./coins');
var networks = require('./networks');
var ops = require('bitcoin-ops');
var typeforce = require('typeforce');
var types = require('./types');
var scriptTypes = btemplates.types;
var SIGNABLE = [btemplates.types.P2PKH, btemplates.types.P2PK, btemplates.types.MULTISIG];
var P2SH = SIGNABLE.concat([btemplates.types.P2WPKH, btemplates.types.P2WSH]);
var ECPair = require('./ecpair');
var ECSignature = require('./ecsignature');
var Transaction = require('./transaction');
var debug = require('debug')('bitgo:utxolib:txbuilder');
function supportedType(type) {
    return SIGNABLE.indexOf(type) !== -1;
}
function supportedP2SHType(type) {
    return P2SH.indexOf(type) !== -1;
}
function extractChunks(type, chunks, script) {
    var pubKeys = [];
    var signatures = [];
    switch (type) {
        case scriptTypes.P2PKH:
            // if (redeemScript) throw new Error('Nonstandard... P2SH(P2PKH)')
            pubKeys = chunks.slice(1);
            signatures = chunks.slice(0, 1);
            break;
        case scriptTypes.P2PK:
            pubKeys[0] = script ? btemplates.pubKey.output.decode(script) : undefined;
            signatures = chunks.slice(0, 1);
            break;
        case scriptTypes.MULTISIG:
            if (script) {
                var multisig = btemplates.multisig.output.decode(script);
                pubKeys = multisig.pubKeys;
            }
            signatures = chunks.slice(1).map(function (chunk) {
                return chunk.length === 0 ? undefined : chunk;
            });
            break;
    }
    return {
        pubKeys: pubKeys,
        signatures: signatures
    };
}
function expandInput(scriptSig, witnessStack) {
    if (scriptSig.length === 0 && witnessStack.length === 0)
        return {};
    var prevOutScript;
    var prevOutType;
    var scriptType;
    var script;
    var redeemScript;
    var witnessScript;
    var witnessScriptType;
    var redeemScriptType;
    var witness = false;
    var p2wsh = false;
    var p2sh = false;
    var witnessProgram;
    var chunks;
    var scriptSigChunks = bscript.decompile(scriptSig);
    var sigType = btemplates.classifyInput(scriptSigChunks, true);
    if (sigType === scriptTypes.P2SH) {
        p2sh = true;
        redeemScript = scriptSigChunks[scriptSigChunks.length - 1];
        redeemScriptType = btemplates.classifyOutput(redeemScript);
        prevOutScript = btemplates.scriptHash.output.encode(bcrypto.hash160(redeemScript));
        prevOutType = scriptTypes.P2SH;
        script = redeemScript;
    }
    var classifyWitness = btemplates.classifyWitness(witnessStack, true);
    if (classifyWitness === scriptTypes.P2WSH) {
        witnessScript = witnessStack[witnessStack.length - 1];
        witnessScriptType = btemplates.classifyOutput(witnessScript);
        p2wsh = true;
        witness = true;
        if (scriptSig.length === 0) {
            prevOutScript = btemplates.witnessScriptHash.output.encode(bcrypto.sha256(witnessScript));
            prevOutType = scriptTypes.P2WSH;
            if (redeemScript !== undefined) {
                throw new Error('Redeem script given when unnecessary');
            }
            // bare witness
        }
        else {
            if (!redeemScript) {
                throw new Error('No redeemScript provided for P2WSH, but scriptSig non-empty');
            }
            witnessProgram = btemplates.witnessScriptHash.output.encode(bcrypto.sha256(witnessScript));
            if (!redeemScript.equals(witnessProgram)) {
                throw new Error('Redeem script didn\'t match witnessScript');
            }
        }
        if (!supportedType(btemplates.classifyOutput(witnessScript))) {
            throw new Error('unsupported witness script');
        }
        script = witnessScript;
        scriptType = witnessScriptType;
        chunks = witnessStack.slice(0, -1);
    }
    else if (classifyWitness === scriptTypes.P2WPKH) {
        witness = true;
        var key = witnessStack[witnessStack.length - 1];
        var keyHash = bcrypto.hash160(key);
        if (scriptSig.length === 0) {
            prevOutScript = btemplates.witnessPubKeyHash.output.encode(keyHash);
            prevOutType = scriptTypes.P2WPKH;
            if (typeof redeemScript !== 'undefined') {
                throw new Error('Redeem script given when unnecessary');
            }
        }
        else {
            if (!redeemScript) {
                throw new Error('No redeemScript provided for P2WPKH, but scriptSig wasn\'t empty');
            }
            witnessProgram = btemplates.witnessPubKeyHash.output.encode(keyHash);
            if (!redeemScript.equals(witnessProgram)) {
                throw new Error('Redeem script did not have the right witness program');
            }
        }
        scriptType = scriptTypes.P2PKH;
        chunks = witnessStack;
    }
    else if (redeemScript) {
        if (!supportedP2SHType(redeemScriptType)) {
            throw new Error('Bad redeemscript!');
        }
        script = redeemScript;
        scriptType = redeemScriptType;
        chunks = scriptSigChunks.slice(0, -1);
    }
    else {
        prevOutType = scriptType = btemplates.classifyInput(scriptSig);
        chunks = scriptSigChunks;
    }
    var expanded = extractChunks(scriptType, chunks, script);
    var result = {
        pubKeys: expanded.pubKeys,
        signatures: expanded.signatures,
        prevOutScript: prevOutScript,
        prevOutType: prevOutType,
        signType: scriptType,
        signScript: script,
        witness: Boolean(witness)
    };
    if (p2sh) {
        result.redeemScript = redeemScript;
        result.redeemScriptType = redeemScriptType;
    }
    if (p2wsh) {
        result.witnessScript = witnessScript;
        result.witnessScriptType = witnessScriptType;
    }
    return result;
}
// could be done in expandInput, but requires the original Transaction for hashForSignature
function fixMultisigOrder(input, transaction, vin, value, network) {
    if (input.redeemScriptType !== scriptTypes.MULTISIG || !input.redeemScript)
        return;
    if (input.pubKeys.length === input.signatures.length)
        return;
    network = network || networks.bitcoin;
    var unmatched = input.signatures.concat();
    input.signatures = input.pubKeys.map(function (pubKey) {
        var keyPair = ECPair.fromPublicKeyBuffer(pubKey);
        var match;
        // check for a signature
        unmatched.some(function (signature, i) {
            // skip if undefined || OP_0
            if (!signature)
                return false;
            // TODO: avoid O(n) hashForSignature
            var parsed = ECSignature.parseScriptSignature(signature);
            var hash;
            switch (network.coin) {
                case coins.BSV:
                case coins.BCH:
                    hash = transaction.hashForCashSignature(vin, input.signScript, value, parsed.hashType);
                    break;
                case coins.BTG:
                    hash = transaction.hashForGoldSignature(vin, input.signScript, value, parsed.hashType);
                    break;
                case coins.ZEC:
                    if (value === undefined) {
                        return false;
                    }
                    hash = transaction.hashForZcashSignature(vin, input.signScript, value, parsed.hashType);
                    break;
                default:
                    if (input.witness) {
                        hash = transaction.hashForWitnessV0(vin, input.signScript, value, parsed.hashType);
                    }
                    else {
                        hash = transaction.hashForSignature(vin, input.signScript, parsed.hashType);
                    }
                    break;
            }
            // skip if signature does not match pubKey
            if (!keyPair.verify(hash, parsed.signature))
                return false;
            // remove matched signature from unmatched
            unmatched[i] = undefined;
            match = signature;
            return true;
        });
        return match;
    });
}
function expandOutput(script, scriptType, ourPubKey) {
    typeforce(types.Buffer, script);
    var scriptChunks = bscript.decompile(script);
    if (!scriptType) {
        scriptType = btemplates.classifyOutput(script);
    }
    var pubKeys = [];
    switch (scriptType) {
        // does our hash160(pubKey) match the output scripts?
        case scriptTypes.P2PKH:
            if (!ourPubKey)
                break;
            var pkh1 = scriptChunks[2];
            var pkh2 = bcrypto.hash160(ourPubKey);
            if (pkh1.equals(pkh2))
                pubKeys = [ourPubKey];
            break;
        // does our hash160(pubKey) match the output scripts?
        case scriptTypes.P2WPKH:
            if (!ourPubKey)
                break;
            var wpkh1 = scriptChunks[1];
            var wpkh2 = bcrypto.hash160(ourPubKey);
            if (wpkh1.equals(wpkh2))
                pubKeys = [ourPubKey];
            break;
        case scriptTypes.P2PK:
            pubKeys = scriptChunks.slice(0, 1);
            break;
        case scriptTypes.MULTISIG:
            pubKeys = scriptChunks.slice(1, -2);
            break;
        default: return { scriptType: scriptType };
    }
    return {
        pubKeys: pubKeys,
        scriptType: scriptType,
        signatures: pubKeys.map(function () { return undefined; })
    };
}
function checkP2SHInput(input, redeemScriptHash) {
    if (input.prevOutType) {
        if (input.prevOutType !== scriptTypes.P2SH)
            throw new Error('PrevOutScript must be P2SH');
        var prevOutScriptScriptHash = bscript.decompile(input.prevOutScript)[1];
        if (!prevOutScriptScriptHash.equals(redeemScriptHash))
            throw new Error('Inconsistent hash160(RedeemScript)');
    }
}
function checkP2WSHInput(input, witnessScriptHash) {
    if (input.prevOutType) {
        if (input.prevOutType !== scriptTypes.P2WSH)
            throw new Error('PrevOutScript must be P2WSH');
        var scriptHash = bscript.decompile(input.prevOutScript)[1];
        if (!scriptHash.equals(witnessScriptHash))
            throw new Error('Inconsistent sha25(WitnessScript)');
    }
}
function prepareInput(input, kpPubKey, redeemScript, witnessValue, witnessScript) {
    var expanded;
    var prevOutType;
    var prevOutScript;
    var p2sh = false;
    var p2shType;
    var redeemScriptHash;
    var witness = false;
    var p2wsh = false;
    var witnessType;
    var witnessScriptHash;
    var signType;
    var signScript;
    if (redeemScript && witnessScript) {
        redeemScriptHash = bcrypto.hash160(redeemScript);
        witnessScriptHash = bcrypto.sha256(witnessScript);
        checkP2SHInput(input, redeemScriptHash);
        if (!redeemScript.equals(btemplates.witnessScriptHash.output.encode(witnessScriptHash)))
            throw new Error('Witness script inconsistent with redeem script');
        expanded = expandOutput(witnessScript, undefined, kpPubKey);
        if (!expanded.pubKeys)
            throw new Error('WitnessScript not supported "' + bscript.toASM(redeemScript) + '"');
        prevOutType = btemplates.types.P2SH;
        prevOutScript = btemplates.scriptHash.output.encode(redeemScriptHash);
        p2sh = witness = p2wsh = true;
        p2shType = btemplates.types.P2WSH;
        signType = witnessType = expanded.scriptType;
        signScript = witnessScript;
    }
    else if (redeemScript) {
        redeemScriptHash = bcrypto.hash160(redeemScript);
        checkP2SHInput(input, redeemScriptHash);
        expanded = expandOutput(redeemScript, undefined, kpPubKey);
        if (!expanded.pubKeys)
            throw new Error('RedeemScript not supported "' + bscript.toASM(redeemScript) + '"');
        prevOutType = btemplates.types.P2SH;
        prevOutScript = btemplates.scriptHash.output.encode(redeemScriptHash);
        p2sh = true;
        signType = p2shType = expanded.scriptType;
        signScript = redeemScript;
        witness = signType === btemplates.types.P2WPKH;
    }
    else if (witnessScript) {
        witnessScriptHash = bcrypto.sha256(witnessScript);
        checkP2WSHInput(input, witnessScriptHash);
        expanded = expandOutput(witnessScript, undefined, kpPubKey);
        if (!expanded.pubKeys)
            throw new Error('WitnessScript not supported "' + bscript.toASM(redeemScript) + '"');
        prevOutType = btemplates.types.P2WSH;
        prevOutScript = btemplates.witnessScriptHash.output.encode(witnessScriptHash);
        witness = p2wsh = true;
        signType = witnessType = expanded.scriptType;
        signScript = witnessScript;
    }
    else if (input.prevOutType) {
        // embedded scripts are not possible without a redeemScript
        if (input.prevOutType === scriptTypes.P2SH ||
            input.prevOutType === scriptTypes.P2WSH) {
            throw new Error('PrevOutScript is ' + input.prevOutType + ', requires redeemScript');
        }
        prevOutType = input.prevOutType;
        prevOutScript = input.prevOutScript;
        expanded = expandOutput(input.prevOutScript, input.prevOutType, kpPubKey);
        if (!expanded.pubKeys)
            return;
        witness = (input.prevOutType === scriptTypes.P2WPKH);
        signType = prevOutType;
        signScript = prevOutScript;
    }
    else {
        prevOutScript = btemplates.pubKeyHash.output.encode(bcrypto.hash160(kpPubKey));
        expanded = expandOutput(prevOutScript, scriptTypes.P2PKH, kpPubKey);
        prevOutType = scriptTypes.P2PKH;
        witness = false;
        signType = prevOutType;
        signScript = prevOutScript;
    }
    if (signType === scriptTypes.P2WPKH) {
        signScript = btemplates.pubKeyHash.output.encode(btemplates.witnessPubKeyHash.output.decode(signScript));
    }
    if (p2sh) {
        input.redeemScript = redeemScript;
        input.redeemScriptType = p2shType;
    }
    if (p2wsh) {
        input.witnessScript = witnessScript;
        input.witnessScriptType = witnessType;
    }
    input.pubKeys = expanded.pubKeys;
    input.signatures = expanded.signatures;
    input.signScript = signScript;
    input.signType = signType;
    input.prevOutScript = prevOutScript;
    input.prevOutType = prevOutType;
    input.witness = witness;
}
function buildStack(type, signatures, pubKeys, allowIncomplete) {
    if (type === scriptTypes.P2PKH) {
        if (signatures.length === 1 && Buffer.isBuffer(signatures[0]) && pubKeys.length === 1)
            return btemplates.pubKeyHash.input.encodeStack(signatures[0], pubKeys[0]);
    }
    else if (type === scriptTypes.P2PK) {
        if (signatures.length === 1 && Buffer.isBuffer(signatures[0]))
            return btemplates.pubKey.input.encodeStack(signatures[0]);
    }
    else if (type === scriptTypes.MULTISIG) {
        if (signatures.length > 0) {
            signatures = signatures.map(function (signature) {
                return signature || ops.OP_0;
            });
            if (!allowIncomplete) {
                // remove blank signatures
                signatures = signatures.filter(function (x) { return x !== ops.OP_0; });
            }
            return btemplates.multisig.input.encodeStack(signatures);
        }
    }
    else {
        throw new Error('Not yet supported');
    }
    if (!allowIncomplete)
        throw new Error('Not enough signatures provided');
    return [];
}
function buildInput(input, allowIncomplete) {
    var scriptType = input.prevOutType;
    var sig = [];
    var witness = [];
    if (supportedType(scriptType)) {
        sig = buildStack(scriptType, input.signatures, input.pubKeys, allowIncomplete);
    }
    var p2sh = false;
    if (scriptType === btemplates.types.P2SH) {
        // We can remove this error later when we have a guarantee prepareInput
        // rejects unsignable scripts - it MUST be signable at this point.
        if (!allowIncomplete && !supportedP2SHType(input.redeemScriptType)) {
            throw new Error('Impossible to sign this type');
        }
        if (supportedType(input.redeemScriptType)) {
            sig = buildStack(input.redeemScriptType, input.signatures, input.pubKeys, allowIncomplete);
        }
        // If it wasn't SIGNABLE, it's witness, defer to that
        if (input.redeemScriptType) {
            p2sh = true;
            scriptType = input.redeemScriptType;
        }
    }
    switch (scriptType) {
        // P2WPKH is a special case of P2PKH
        case btemplates.types.P2WPKH:
            witness = buildStack(btemplates.types.P2PKH, input.signatures, input.pubKeys, allowIncomplete);
            break;
        case btemplates.types.P2WSH:
            // We can remove this check later
            if (!allowIncomplete && !supportedType(input.witnessScriptType)) {
                throw new Error('Impossible to sign this type');
            }
            if (supportedType(input.witnessScriptType)) {
                witness = buildStack(input.witnessScriptType, input.signatures, input.pubKeys, allowIncomplete);
                witness.push(input.witnessScript);
                scriptType = input.witnessScriptType;
            }
            break;
    }
    // append redeemScript if necessary
    if (p2sh) {
        sig.push(input.redeemScript);
    }
    return {
        type: scriptType,
        script: bscript.compile(sig),
        witness: witness
    };
}
// By default, assume is a bitcoin transaction
function TransactionBuilder(network, maximumFeeRate) {
    this.prevTxMap = {};
    this.network = network || networks.bitcoin;
    // WARNING: This is __NOT__ to be relied on, its just another potential safety mechanism (safety in-depth)
    this.maximumFeeRate = maximumFeeRate || 2500;
    this.inputs = [];
    this.tx = new Transaction(this.network);
}
TransactionBuilder.prototype.setLockTime = function (locktime) {
    typeforce(types.UInt32, locktime);
    // if any signatures exist, throw
    if (this.inputs.some(function (input) {
        if (!input.signatures)
            return false;
        return input.signatures.some(function (s) { return s; });
    })) {
        throw new Error('No, this would invalidate signatures');
    }
    this.tx.locktime = locktime;
};
TransactionBuilder.prototype.setVersion = function (version, overwinter) {
    if (overwinter === void 0) { overwinter = true; }
    typeforce(types.UInt32, version);
    if (coins.isZcash(this.network)) {
        if (!this.network.consensusBranchId.hasOwnProperty(this.tx.version)) {
            throw new Error('Unsupported Zcash transaction');
        }
        this.tx.overwintered = (overwinter ? 1 : 0);
        this.tx.consensusBranchId = this.network.consensusBranchId[version];
    }
    this.tx.version = version;
};
TransactionBuilder.prototype.setConsensusBranchId = function (consensusBranchId) {
    if (!coins.isZcash(this.network)) {
        throw new Error('consensusBranchId can only be set for Zcash transactions');
    }
    if (!this.inputs.every(function (input) { return input.signatures === undefined; })) {
        throw new Error('Changing the consensusBranchId for a partially signed transaction would invalidate signatures');
    }
    typeforce(types.UInt32, consensusBranchId);
    this.tx.consensusBranchId = consensusBranchId;
};
TransactionBuilder.prototype.setVersionGroupId = function (versionGroupId) {
    if (!(coins.isZcash(this.network) && this.tx.isOverwinterCompatible())) {
        throw new Error('expiryHeight can only be set for Zcash starting at overwinter version. Current network coin: ' +
            this.network.coin + ', version: ' + this.tx.version);
    }
    typeforce(types.UInt32, versionGroupId);
    this.tx.versionGroupId = versionGroupId;
};
TransactionBuilder.prototype.setExpiryHeight = function (expiryHeight) {
    if (!(coins.isZcash(this.network) && this.tx.isOverwinterCompatible())) {
        throw new Error('expiryHeight can only be set for Zcash starting at overwinter version. Current network coin: ' +
            this.network.coin + ', version: ' + this.tx.version);
    }
    typeforce(types.UInt32, expiryHeight);
    this.tx.expiryHeight = expiryHeight;
};
TransactionBuilder.prototype.setJoinSplits = function (transaction) {
    if (!(coins.isZcash(this.network) && this.tx.supportsJoinSplits())) {
        throw new Error('joinsplits can only be set for Zcash starting at version 2. Current network coin: ' +
            this.network.coin + ', version: ' + this.tx.version);
    }
    if (transaction && transaction.joinsplits) {
        this.tx.joinsplits = transaction.joinsplits.map(function (txJoinsplit) {
            return {
                vpubOld: txJoinsplit.vpubOld,
                vpubNew: txJoinsplit.vpubNew,
                anchor: txJoinsplit.anchor,
                nullifiers: txJoinsplit.nullifiers,
                commitments: txJoinsplit.commitments,
                ephemeralKey: txJoinsplit.ephemeralKey,
                randomSeed: txJoinsplit.randomSeed,
                macs: txJoinsplit.macs,
                zproof: txJoinsplit.zproof,
                ciphertexts: txJoinsplit.ciphertexts
            };
        });
        this.tx.joinsplitPubkey = transaction.joinsplitPubkey;
        this.tx.joinsplitSig = transaction.joinsplitSig;
        return;
    }
    throw new Error('Invalid transaction with joinsplits');
};
TransactionBuilder.fromTransaction = function (transaction, network) {
    var txbNetwork = network || networks.bitcoin;
    var txb = new TransactionBuilder(txbNetwork);
    if (txb.network.coin !== transaction.network.coin) {
        throw new Error('This transaction is incompatible with the transaction builder');
    }
    // Copy transaction fields
    txb.setVersion(transaction.version, transaction.overwintered);
    txb.setLockTime(transaction.locktime);
    if (coins.isZcash(txbNetwork)) {
        // Copy Zcash overwinter fields. Omitted if the transaction builder is not for Zcash.
        if (txb.tx.isOverwinterCompatible()) {
            txb.setVersionGroupId(transaction.versionGroupId);
            txb.setExpiryHeight(transaction.expiryHeight);
        }
        // We don't support protected transactions but we copy the joinsplits for consistency. However, the transaction
        // builder will fail when we try to sign one of these transactions
        if (txb.tx.supportsJoinSplits()) {
            txb.setJoinSplits(transaction);
        }
        txb.setConsensusBranchId(transaction.consensusBranchId);
    }
    // Copy Dash special transaction fields. Omitted if the transaction builder is not for Dash.
    if (coins.isDash(txbNetwork)) {
        typeforce(types.UInt16, transaction.type);
        txb.tx.type = transaction.type;
        if (txb.tx.versionSupportsDashSpecialTransactions()) {
            typeforce(types.Buffer, transaction.extraPayload);
            txb.tx.extraPayload = transaction.extraPayload;
        }
    }
    // Copy outputs (done first to avoid signature invalidation)
    transaction.outs.forEach(function (txOut) {
        txb.addOutput(txOut.script, txOut.value);
    });
    // Copy inputs
    transaction.ins.forEach(function (txIn) {
        txb.__addInputUnsafe(txIn.hash, txIn.index, {
            sequence: txIn.sequence,
            script: txIn.script,
            witness: txIn.witness,
            value: txIn.value
        });
    });
    // fix some things not possible through the public API
    txb.inputs.forEach(function (input, i) {
        fixMultisigOrder(input, transaction, i, input.value, txbNetwork);
    });
    return txb;
};
TransactionBuilder.prototype.addInput = function (txHash, vout, sequence, prevOutScript) {
    if (!this.__canModifyInputs()) {
        throw new Error('No, this would invalidate signatures');
    }
    var value;
    // is it a hex string?
    if (typeof txHash === 'string') {
        // transaction hashs's are displayed in reverse order, un-reverse it
        txHash = Buffer.from(txHash, 'hex').reverse();
        // is it a Transaction object?
    }
    else if (txHash instanceof Transaction) {
        var txOut = txHash.outs[vout];
        prevOutScript = txOut.script;
        value = txOut.value;
        txHash = txHash.getHash();
    }
    return this.__addInputUnsafe(txHash, vout, {
        sequence: sequence,
        prevOutScript: prevOutScript,
        value: value
    });
};
TransactionBuilder.prototype.__addInputUnsafe = function (txHash, vout, options) {
    if (Transaction.isCoinbaseHash(txHash)) {
        throw new Error('coinbase inputs not supported');
    }
    var prevTxOut = txHash.toString('hex') + ':' + vout;
    if (this.prevTxMap[prevTxOut] !== undefined)
        throw new Error('Duplicate TxOut: ' + prevTxOut);
    var input = {};
    // derive what we can from the scriptSig
    if (options.script !== undefined) {
        input = expandInput(options.script, options.witness || []);
    }
    // if an input value was given, retain it
    if (options.value !== undefined) {
        input.value = options.value;
    }
    // derive what we can from the previous transactions output script
    if (!input.prevOutScript && options.prevOutScript) {
        var prevOutType;
        if (!input.pubKeys && !input.signatures) {
            var expanded = expandOutput(options.prevOutScript);
            if (expanded.pubKeys) {
                input.pubKeys = expanded.pubKeys;
                input.signatures = expanded.signatures;
            }
            prevOutType = expanded.scriptType;
        }
        input.prevOutScript = options.prevOutScript;
        input.prevOutType = prevOutType || btemplates.classifyOutput(options.prevOutScript);
    }
    var vin = this.tx.addInput(txHash, vout, options.sequence, options.scriptSig);
    this.inputs[vin] = input;
    this.prevTxMap[prevTxOut] = vin;
    return vin;
};
TransactionBuilder.prototype.addOutput = function (scriptPubKey, value) {
    if (!this.__canModifyOutputs()) {
        throw new Error('No, this would invalidate signatures');
    }
    // Attempt to get a script if it's a base58 address string
    if (typeof scriptPubKey === 'string') {
        scriptPubKey = baddress.toOutputScript(scriptPubKey, this.network);
    }
    return this.tx.addOutput(scriptPubKey, value);
};
TransactionBuilder.prototype.build = function () {
    return this.__build(false);
};
TransactionBuilder.prototype.buildIncomplete = function () {
    return this.__build(true);
};
TransactionBuilder.prototype.__build = function (allowIncomplete) {
    if (!allowIncomplete) {
        if (!this.tx.ins.length)
            throw new Error('Transaction has no inputs');
        if (!this.tx.outs.length)
            throw new Error('Transaction has no outputs');
    }
    var tx = this.tx.clone();
    // Create script signatures from inputs
    this.inputs.forEach(function (input, i) {
        var scriptType = input.witnessScriptType || input.redeemScriptType || input.prevOutType;
        if (!scriptType && !allowIncomplete)
            throw new Error('Transaction is not complete');
        var result = buildInput(input, allowIncomplete);
        // skip if no result
        if (!allowIncomplete) {
            if (!supportedType(result.type) && result.type !== btemplates.types.P2WPKH) {
                throw new Error(result.type + ' not supported');
            }
        }
        tx.setInputScript(i, result.script);
        tx.setWitness(i, result.witness);
    });
    if (!allowIncomplete) {
        // do not rely on this, its merely a last resort
        if (this.__overMaximumFees(tx.virtualSize())) {
            throw new Error('Transaction has absurd fees');
        }
    }
    return tx;
};
function canSign(input) {
    return input.prevOutScript !== undefined &&
        input.signScript !== undefined &&
        input.pubKeys !== undefined &&
        input.signatures !== undefined &&
        input.signatures.length === input.pubKeys.length &&
        input.pubKeys.length > 0 &&
        (input.witness === false ||
            (input.witness === true && input.value !== undefined));
}
TransactionBuilder.prototype.sign = function (vin, keyPair, redeemScript, hashType, witnessValue, witnessScript) {
    debug('Signing transaction: (input: %d, hashType: %d, witnessVal: %s, witnessScript: %j)', vin, hashType, witnessValue, witnessScript);
    debug('Transaction Builder network: %j', this.network);
    // TODO: remove keyPair.network matching in 4.0.0
    if (keyPair.network && keyPair.network !== this.network)
        throw new TypeError('Inconsistent network');
    if (!this.inputs[vin])
        throw new Error('No input at index: ' + vin);
    hashType = hashType || Transaction.SIGHASH_ALL;
    var input = this.inputs[vin];
    // if redeemScript was previously provided, enforce consistency
    if (input.redeemScript !== undefined &&
        redeemScript &&
        !input.redeemScript.equals(redeemScript)) {
        throw new Error('Inconsistent redeemScript');
    }
    var kpPubKey = keyPair.publicKey || keyPair.getPublicKeyBuffer();
    if (!canSign(input)) {
        if (witnessValue !== undefined) {
            if (input.value !== undefined && input.value !== witnessValue)
                throw new Error('Input didn\'t match witnessValue');
            typeforce(types.Satoshi, witnessValue);
            input.value = witnessValue;
        }
        debug('Preparing input %d for signing', vin);
        if (!canSign(input))
            prepareInput(input, kpPubKey, redeemScript, witnessValue, witnessScript);
        if (!canSign(input))
            throw Error(input.prevOutType + ' not supported');
    }
    // ready to sign
    var signatureHash;
    if (coins.isBitcoinGold(this.network)) {
        signatureHash = this.tx.hashForGoldSignature(vin, input.signScript, witnessValue, hashType, input.witness);
        debug('Calculated BTG sighash (%s)', signatureHash.toString('hex'));
    }
    else if (coins.isBitcoinCash(this.network) || coins.isBitcoinSV(this.network)) {
        signatureHash = this.tx.hashForCashSignature(vin, input.signScript, witnessValue, hashType);
        debug('Calculated BCH sighash (%s)', signatureHash.toString('hex'));
    }
    else if (coins.isZcash(this.network)) {
        signatureHash = this.tx.hashForZcashSignature(vin, input.signScript, witnessValue, hashType);
        debug('Calculated ZEC sighash (%s)', signatureHash.toString('hex'));
    }
    else {
        if (input.witness) {
            signatureHash = this.tx.hashForWitnessV0(vin, input.signScript, witnessValue, hashType);
            debug('Calculated witnessv0 sighash (%s)', signatureHash.toString('hex'));
        }
        else {
            signatureHash = this.tx.hashForSignature(vin, input.signScript, hashType);
            debug('Calculated sighash (%s)', signatureHash.toString('hex'));
        }
    }
    // enforce in order signing of public keys
    var signed = input.pubKeys.some(function (pubKey, i) {
        if (!kpPubKey.equals(pubKey))
            return false;
        if (input.signatures[i])
            throw new Error('Signature already exists');
        if (kpPubKey.length !== 33 &&
            input.signType === scriptTypes.P2WPKH)
            throw new Error('BIP143 rejects uncompressed public keys in P2WPKH or P2WSH');
        var signature = keyPair.sign(signatureHash);
        if (Buffer.isBuffer(signature))
            signature = ECSignature.fromRSBuffer(signature);
        debug('Produced signature (r: %s, s: %s)', signature.r, signature.s);
        input.signatures[i] = signature.toScriptSignature(hashType);
        return true;
    });
    if (!signed)
        throw new Error('Key pair cannot sign for this input');
};
function signatureHashType(buffer) {
    return buffer.readUInt8(buffer.length - 1);
}
TransactionBuilder.prototype.__canModifyInputs = function () {
    return this.inputs.every(function (input) {
        // any signatures?
        if (input.signatures === undefined)
            return true;
        return input.signatures.every(function (signature) {
            if (!signature)
                return true;
            var hashType = signatureHashType(signature);
            // if SIGHASH_ANYONECANPAY is set, signatures would not
            // be invalidated by more inputs
            return hashType & Transaction.SIGHASH_ANYONECANPAY;
        });
    });
};
TransactionBuilder.prototype.__canModifyOutputs = function () {
    var nInputs = this.tx.ins.length;
    var nOutputs = this.tx.outs.length;
    return this.inputs.every(function (input) {
        if (input.signatures === undefined)
            return true;
        return input.signatures.every(function (signature) {
            if (!signature)
                return true;
            var hashType = signatureHashType(signature);
            var hashTypeMod = hashType & 0x1f;
            if (hashTypeMod === Transaction.SIGHASH_NONE)
                return true;
            if (hashTypeMod === Transaction.SIGHASH_SINGLE) {
                // if SIGHASH_SINGLE is set, and nInputs > nOutputs
                // some signatures would be invalidated by the addition
                // of more outputs
                return nInputs <= nOutputs;
            }
        });
    });
};
TransactionBuilder.prototype.__overMaximumFees = function (bytes) {
    // not all inputs will have .value defined
    var incoming = this.inputs.reduce(function (a, x) { return a + (x.value >>> 0); }, 0);
    // but all outputs do, and if we have any input value
    // we can immediately determine if the outputs are too small
    var outgoing = this.tx.outs.reduce(function (a, x) { return a + x.value; }, 0);
    var fee = incoming - outgoing;
    var feeRate = fee / bytes;
    return feeRate > this.maximumFeeRate;
};
module.exports = TransactionBuilder;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidHJhbnNhY3Rpb25fYnVpbGRlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cmFuc2FjdGlvbl9idWlsZGVyLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLElBQUksTUFBTSxHQUFHLE9BQU8sQ0FBQyxhQUFhLENBQUMsQ0FBQyxNQUFNLENBQUE7QUFDMUMsSUFBSSxRQUFRLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFBO0FBQ25DLElBQUksT0FBTyxHQUFHLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQTtBQUNqQyxJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUE7QUFDakMsSUFBSSxVQUFVLEdBQUcsT0FBTyxDQUFDLGFBQWEsQ0FBQyxDQUFBO0FBQ3ZDLElBQUksS0FBSyxHQUFHLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQTtBQUM5QixJQUFJLFFBQVEsR0FBRyxPQUFPLENBQUMsWUFBWSxDQUFDLENBQUE7QUFDcEMsSUFBSSxHQUFHLEdBQUcsT0FBTyxDQUFDLGFBQWEsQ0FBQyxDQUFBO0FBQ2hDLElBQUksU0FBUyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQTtBQUNwQyxJQUFJLEtBQUssR0FBRyxPQUFPLENBQUMsU0FBUyxDQUFDLENBQUE7QUFDOUIsSUFBSSxXQUFXLEdBQUcsVUFBVSxDQUFDLEtBQUssQ0FBQTtBQUNsQyxJQUFJLFFBQVEsR0FBRyxDQUFDLFVBQVUsQ0FBQyxLQUFLLENBQUMsS0FBSyxFQUFFLFVBQVUsQ0FBQyxLQUFLLENBQUMsSUFBSSxFQUFFLFVBQVUsQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLENBQUE7QUFDekYsSUFBSSxJQUFJLEdBQUcsUUFBUSxDQUFDLE1BQU0sQ0FBQyxDQUFDLFVBQVUsQ0FBQyxLQUFLLENBQUMsTUFBTSxFQUFFLFVBQVUsQ0FBQyxLQUFLLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQTtBQUU3RSxJQUFJLE1BQU0sR0FBRyxP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QUE7SUFDSixDQUFDLENBQUMsQ0FBQTtBQUNKLENBQUMsQ0FBQTtBQUVELGtCQUFrQixDQUFDLFNBQVMsQ0FBQyxpQkFBaUIsR0FBRyxVQUFVLEtBQUs7SUFDOUQsMENBQTBDO0lBQzFDLElBQUksUUFBUSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxFQUFFLENBQUMsSUFBSSxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxLQUFLLEtBQUssQ0FBQyxDQUFDLENBQUEsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUE7SUFFcEYscURBQXFEO0lBQ3JELDREQUE0RDtJQUM1RCxJQUFJLFFBQVEsR0FBRyxJQUFJLENBQUMsRUFBRSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsVUFBVSxDQUFDLEVBQUUsQ0FBQyxJQUFJLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxLQUFLLENBQUEsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUE7SUFDN0UsSUFBSSxHQUFHLEdBQUcsUUFBUSxHQUFHLFFBQVEsQ0FBQTtJQUM3QixJQUFJLE9BQU8sR0FBRyxHQUFHLEdBQUcsS0FBSyxDQUFBO0lBRXpCLE9BQU8sT0FBTyxHQUFHLElBQUksQ0FBQyxjQUFjLENBQUE7QUFDdEMsQ0FBQyxDQUFBO0FBRUQsTUFBTSxDQUFDLE9BQU8sR0FBRyxrQkFBa0IsQ0FBQSIsInNvdXJjZXNDb250ZW50IjpbInZhciBCdWZmZXIgPSByZXF1aXJlKCdzYWZlLWJ1ZmZlcicpLkJ1ZmZlclxudmFyIGJhZGRyZXNzID0gcmVxdWlyZSgnLi9hZGRyZXNzJylcbnZhciBiY3J5cHRvID0gcmVxdWlyZSgnLi9jcnlwdG8nKVxudmFyIGJzY3JpcHQgPSByZXF1aXJlKCcuL3NjcmlwdCcpXG52YXIgYnRlbXBsYXRlcyA9IHJlcXVpcmUoJy4vdGVtcGxhdGVzJylcbnZhciBjb2lucyA9IHJlcXVpcmUoJy4vY29pbnMnKVxudmFyIG5ldHdvcmtzID0gcmVxdWlyZSgnLi9uZXR3b3JrcycpXG52YXIgb3BzID0gcmVxdWlyZSgnYml0Y29pbi1vcHMnKVxudmFyIHR5cGVmb3JjZSA9IHJlcXVpcmUoJ3R5cGVmb3JjZScpXG52YXIgdHlwZXMgPSByZXF1aXJlKCcuL3R5cGVzJylcbnZhciBzY3JpcHRUeXBlcyA9IGJ0ZW1wbGF0ZXMudHlwZXNcbnZhciBTSUdOQUJMRSA9IFtidGVtcGxhdGVzLnR5cGVzLlAyUEtILCBidGVtcGxhdGVzLnR5cGVzLlAyUEssIGJ0ZW1wbGF0ZXMudHlwZXMuTVVMVElTSUddXG52YXIgUDJTSCA9IFNJR05BQkxFLmNvbmNhdChbYnRlbXBsYXRlcy50eXBlcy5QMldQS0gsIGJ0ZW1wbGF0ZXMudHlwZXMuUDJXU0hdKVxuXG52YXIgRUNQYWlyID0gcmVxdWlyZSgnLi9lY3BhaXInKVxudmFyIEVDU2lnbmF0dXJlID0gcmVxdWlyZSgnLi9lY3NpZ25hdHVyZScpXG52YXIgVHJhbnNhY3Rpb24gPSByZXF1aXJlKCcuL3RyYW5zYWN0aW9uJylcblxudmFyIGRlYnVnID0gcmVxdWlyZSgnZGVidWcnKSgnYml0Z286dXR4b2xpYjp0eGJ1aWxkZXInKVxuXG5mdW5jdGlvbiBzdXBwb3J0ZWRUeXBlICh0eXBlKSB7XG4gIHJldHVybiBTSUdOQUJMRS5pbmRleE9mKHR5cGUpICE9PSAtMVxufVxuXG5mdW5jdGlvbiBzdXBwb3J0ZWRQMlNIVHlwZSAodHlwZSkge1xuICByZXR1cm4gUDJTSC5pbmRleE9mKHR5cGUpICE9PSAtMVxufVxuXG5mdW5jdGlvbiBleHRyYWN0Q2h1bmtzICh0eXBlLCBjaHVua3MsIHNjcmlwdCkge1xuICB2YXIgcHViS2V5cyA9IFtdXG4gIHZhciBzaWduYXR1cmVzID0gW11cbiAgc3dpdGNoICh0eXBlKSB7XG4gICAgY2FzZSBzY3JpcHRUeXBlcy5QMlBLSDpcbiAgICAgIC8vIGlmIChyZWRlZW1TY3JpcHQpIHRocm93IG5ldyBFcnJvcignTm9uc3RhbmRhcmQuLi4gUDJTSChQMlBLSCknKVxuICAgICAgcHViS2V5cyA9IGNodW5rcy5zbGljZSgxKVxuICAgICAgc2lnbmF0dXJlcyA9IGNodW5rcy5zbGljZSgwLCAxKVxuICAgICAgYnJlYWtcblxuICAgIGNhc2Ugc2NyaXB0VHlwZXMuUDJQSzpcbiAgICAgIHB1YktleXNbMF0gPSBzY3JpcHQgPyBidGVtcGxhdGVzLnB1YktleS5vdXRwdXQuZGVjb2RlKHNjcmlwdCkgOiB1bmRlZmluZWRcbiAgICAgIHNpZ25hdHVyZXMgPSBjaHVua3Muc2xpY2UoMCwgMSlcbiAgICAgIGJyZWFrXG5cbiAgICBjYXNlIHNjcmlwdFR5cGVzLk1VTFRJU0lHOlxuICAgICAgaWYgKHNjcmlwdCkge1xuICAgICAgICB2YXIgbXVsdGlzaWcgPSBidGVtcGxhdGVzLm11bHRpc2lnLm91dHB1dC5kZWNvZGUoc2NyaXB0KVxuICAgICAgICBwdWJLZXlzID0gbXVsdGlzaWcucHViS2V5c1xuICAgICAgfVxuXG4gICAgICBzaWduYXR1cmVzID0gY2h1bmtzLnNsaWNlKDEpLm1hcChmdW5jdGlvbiAoY2h1bmspIHtcbiAgICAgICAgcmV0dXJuIGNodW5rLmxlbmd0aCA9PT0gMCA/IHVuZGVmaW5lZCA6IGNodW5rXG4gICAgICB9KVxuICAgICAgYnJlYWtcbiAgfVxuXG4gIHJldHVybiB7XG4gICAgcHViS2V5czogcHViS2V5cyxcbiAgICBzaWduYXR1cmVzOiBzaWduYXR1cmVzXG4gIH1cbn1cbmZ1bmN0aW9uIGV4cGFuZElucHV0IChzY3JpcHRTaWcsIHdpdG5lc3NTdGFjaykge1xuICBpZiAoc2NyaXB0U2lnLmxlbmd0aCA9PT0gMCAmJiB3aXRuZXNzU3RhY2subGVuZ3RoID09PSAwKSByZXR1cm4ge31cblxuICB2YXIgcHJldk91dFNjcmlwdFxuICB2YXIgcHJldk91dFR5cGVcbiAgdmFyIHNjcmlwdFR5cGVcbiAgdmFyIHNjcmlwdFxuICB2YXIgcmVkZWVtU2NyaXB0XG4gIHZhciB3aXRuZXNzU2NyaXB0XG4gIHZhciB3aXRuZXNzU2NyaXB0VHlwZVxuICB2YXIgcmVkZWVtU2NyaXB0VHlwZVxuICB2YXIgd2l0bmVzcyA9IGZhbHNlXG4gIHZhciBwMndzaCA9IGZhbHNlXG4gIHZhciBwMnNoID0gZmFsc2VcbiAgdmFyIHdpdG5lc3NQcm9ncmFtXG4gIHZhciBjaHVua3NcblxuICB2YXIgc2NyaXB0U2lnQ2h1bmtzID0gYnNjcmlwdC5kZWNvbXBpbGUoc2NyaXB0U2lnKVxuICB2YXIgc2lnVHlwZSA9IGJ0ZW1wbGF0ZXMuY2xhc3NpZnlJbnB1dChzY3JpcHRTaWdDaHVua3MsIHRydWUpXG4gIGlmIChzaWdUeXBlID09PSBzY3JpcHRUeXBlcy5QMlNIKSB7XG4gICAgcDJzaCA9IHRydWVcbiAgICByZWRlZW1TY3JpcHQgPSBzY3JpcHRTaWdDaHVua3Nbc2NyaXB0U2lnQ2h1bmtzLmxlbmd0aCAtIDFdXG4gICAgcmVkZWVtU2NyaXB0VHlwZSA9IGJ0ZW1wbGF0ZXMuY2xhc3NpZnlPdXRwdXQocmVkZWVtU2NyaXB0KVxuICAgIHByZXZPdXRTY3JpcHQgPSBidGVtcGxhdGVzLnNjcmlwdEhhc2gub3V0cHV0LmVuY29kZShiY3J5cHRvLmhhc2gxNjAocmVkZWVtU2NyaXB0KSlcbiAgICBwcmV2T3V0VHlwZSA9IHNjcmlwdFR5cGVzLlAyU0hcbiAgICBzY3JpcHQgPSByZWRlZW1TY3JpcHRcbiAgfVxuXG4gIHZhciBjbGFzc2lmeVdpdG5lc3MgPSBidGVtcGxhdGVzLmNsYXNzaWZ5V2l0bmVzcyh3aXRuZXNzU3RhY2ssIHRydWUpXG4gIGlmIChjbGFzc2lmeVdpdG5lc3MgPT09IHNjcmlwdFR5cGVzLlAyV1NIKSB7XG4gICAgd2l0bmVzc1NjcmlwdCA9IHdpdG5lc3NTdGFja1t3aXRuZXNzU3RhY2subGVuZ3RoIC0gMV1cbiAgICB3aXRuZXNzU2NyaXB0VHlwZSA9IGJ0ZW1wbGF0ZXMuY2xhc3NpZnlPdXRwdXQod2l0bmVzc1NjcmlwdClcbiAgICBwMndzaCA9IHRydWVcbiAgICB3aXRuZXNzID0gdHJ1ZVxuICAgIGlmIChzY3JpcHRTaWcubGVuZ3RoID09PSAwKSB7XG4gICAgICBwcmV2T3V0U2NyaXB0ID0gYnRlbXBsYXRlcy53aXRuZXNzU2NyaXB0SGFzaC5vdXRwdXQuZW5jb2RlKGJjcnlwdG8uc2hhMjU2KHdpdG5lc3NTY3JpcHQpKVxuICAgICAgcHJldk91dFR5cGUgPSBzY3JpcHRUeXBlcy5QMldTSFxuICAgICAgaWYgKHJlZGVlbVNjcmlwdCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignUmVkZWVtIHNjcmlwdCBnaXZlbiB3aGVuIHVubmVjZXNzYXJ5JylcbiAgICAgIH1cbiAgICAgIC8vIGJhcmUgd2l0bmVzc1xuICAgIH0gZWxzZSB7XG4gICAgICBpZiAoIXJlZGVlbVNjcmlwdCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ05vIHJlZGVlbVNjcmlwdCBwcm92aWRlZCBmb3IgUDJXU0gsIGJ1dCBzY3JpcHRTaWcgbm9uLWVtcHR5JylcbiAgICAgIH1cbiAgICAgIHdpdG5lc3NQcm9ncmFtID0gYnRlbXBsYXRlcy53aXRuZXNzU2NyaXB0SGFzaC5vdXRwdXQuZW5jb2RlKGJjcnlwdG8uc2hhMjU2KHdpdG5lc3NTY3JpcHQpKVxuICAgICAgaWYgKCFyZWRlZW1TY3JpcHQuZXF1YWxzKHdpdG5lc3NQcm9ncmFtKSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1JlZGVlbSBzY3JpcHQgZGlkblxcJ3QgbWF0Y2ggd2l0bmVzc1NjcmlwdCcpXG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKCFzdXBwb3J0ZWRUeXBlKGJ0ZW1wbGF0ZXMuY2xhc3NpZnlPdXRwdXQod2l0bmVzc1NjcmlwdCkpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ3Vuc3VwcG9ydGVkIHdpdG5lc3Mgc2NyaXB0JylcbiAgICB9XG5cbiAgICBzY3JpcHQgPSB3aXRuZXNzU2NyaXB0XG4gICAgc2NyaXB0VHlwZSA9IHdpdG5lc3NTY3JpcHRUeXBlXG4gICAgY2h1bmtzID0gd2l0bmVzc1N0YWNrLnNsaWNlKDAsIC0xKVxuICB9IGVsc2UgaWYgKGNsYXNzaWZ5V2l0bmVzcyA9PT0gc2NyaXB0VHlwZXMuUDJXUEtIKSB7XG4gICAgd2l0bmVzcyA9IHRydWVcbiAgICB2YXIga2V5ID0gd2l0bmVzc1N0YWNrW3dpdG5lc3NTdGFjay5sZW5ndGggLSAxXVxuICAgIHZhciBrZXlIYXNoID0gYmNyeXB0by5oYXNoMTYwKGtleSlcbiAgICBpZiAoc2NyaXB0U2lnLmxlbmd0aCA9PT0gMCkge1xuICAgICAgcHJldk91dFNjcmlwdCA9IGJ0ZW1wbGF0ZXMud2l0bmVzc1B1YktleUhhc2gub3V0cHV0LmVuY29kZShrZXlIYXNoKVxuICAgICAgcHJldk91dFR5cGUgPSBzY3JpcHRUeXBlcy5QMldQS0hcbiAgICAgIGlmICh0eXBlb2YgcmVkZWVtU2NyaXB0ICE9PSAndW5kZWZpbmVkJykge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1JlZGVlbSBzY3JpcHQgZ2l2ZW4gd2hlbiB1bm5lY2Vzc2FyeScpXG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmICghcmVkZWVtU2NyaXB0KSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignTm8gcmVkZWVtU2NyaXB0IHByb3ZpZGVkIGZvciBQMldQS0gsIGJ1dCBzY3JpcHRTaWcgd2FzblxcJ3QgZW1wdHknKVxuICAgICAgfVxuICAgICAgd2l0bmVzc1Byb2dyYW0gPSBidGVtcGxhdGVzLndpdG5lc3NQdWJLZXlIYXNoLm91dHB1dC5lbmNvZGUoa2V5SGFzaClcbiAgICAgIGlmICghcmVkZWVtU2NyaXB0LmVxdWFscyh3aXRuZXNzUHJvZ3JhbSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdSZWRlZW0gc2NyaXB0IGRpZCBub3QgaGF2ZSB0aGUgcmlnaHQgd2l0bmVzcyBwcm9ncmFtJylcbiAgICAgIH1cbiAgICB9XG5cbiAgICBzY3JpcHRUeXBlID0gc2NyaXB0VHlwZXMuUDJQS0hcbiAgICBjaHVua3MgPSB3aXRuZXNzU3RhY2tcbiAgfSBlbHNlIGlmIChyZWRlZW1TY3JpcHQpIHtcbiAgICBpZiAoIXN1cHBvcnRlZFAyU0hUeXBlKHJlZGVlbVNjcmlwdFR5cGUpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0JhZCByZWRlZW1zY3JpcHQhJylcbiAgICB9XG5cbiAgICBzY3JpcHQgPSByZWRlZW1TY3JpcHRcbiAgICBzY3JpcHRUeXBlID0gcmVkZWVtU2NyaXB0VHlwZVxuICAgIGNodW5rcyA9IHNjcmlwdFNpZ0NodW5rcy5zbGljZSgwLCAtMSlcbiAgfSBlbHNlIHtcbiAgICBwcmV2T3V0VHlwZSA9IHNjcmlwdFR5cGUgPSBidGVtcGxhdGVzLmNsYXNzaWZ5SW5wdXQoc2NyaXB0U2lnKVxuICAgIGNodW5rcyA9IHNjcmlwdFNpZ0NodW5rc1xuICB9XG5cbiAgdmFyIGV4cGFuZGVkID0gZXh0cmFjdENodW5rcyhzY3JpcHRUeXBlLCBjaHVua3MsIHNjcmlwdClcblxuICB2YXIgcmVzdWx0ID0ge1xuICAgIHB1YktleXM6IGV4cGFuZGVkLnB1YktleXMsXG4gICAgc2lnbmF0dXJlczogZXhwYW5kZWQuc2lnbmF0dXJlcyxcbiAgICBwcmV2T3V0U2NyaXB0OiBwcmV2T3V0U2NyaXB0LFxuICAgIHByZXZPdXRUeXBlOiBwcmV2T3V0VHlwZSxcbiAgICBzaWduVHlwZTogc2NyaXB0VHlwZSxcbiAgICBzaWduU2NyaXB0OiBzY3JpcHQsXG4gICAgd2l0bmVzczogQm9vbGVhbih3aXRuZXNzKVxuICB9XG5cbiAgaWYgKHAyc2gpIHtcbiAgICByZXN1bHQucmVkZWVtU2NyaXB0ID0gcmVkZWVtU2NyaXB0XG4gICAgcmVzdWx0LnJlZGVlbVNjcmlwdFR5cGUgPSByZWRlZW1TY3JpcHRUeXBlXG4gIH1cblxuICBpZiAocDJ3c2gpIHtcbiAgICByZXN1bHQud2l0bmVzc1NjcmlwdCA9IHdpdG5lc3NTY3JpcHRcbiAgICByZXN1bHQud2l0bmVzc1NjcmlwdFR5cGUgPSB3aXRuZXNzU2NyaXB0VHlwZVxuICB9XG5cbiAgcmV0dXJuIHJlc3VsdFxufVxuXG4vLyBjb3VsZCBiZSBkb25lIGluIGV4cGFuZElucHV0LCBidXQgcmVxdWlyZXMgdGhlIG9yaWdpbmFsIFRyYW5zYWN0aW9uIGZvciBoYXNoRm9yU2lnbmF0dXJlXG5mdW5jdGlvbiBmaXhNdWx0aXNpZ09yZGVyIChpbnB1dCwgdHJhbnNhY3Rpb24sIHZpbiwgdmFsdWUsIG5ldHdvcmspIHtcbiAgaWYgKGlucHV0LnJlZGVlbVNjcmlwdFR5cGUgIT09IHNjcmlwdFR5cGVzLk1VTFRJU0lHIHx8ICFpbnB1dC5yZWRlZW1TY3JpcHQpIHJldHVyblxuICBpZiAoaW5wdXQucHViS2V5cy5sZW5ndGggPT09IGlucHV0LnNpZ25hdHVyZXMubGVuZ3RoKSByZXR1cm5cblxuICBuZXR3b3JrID0gbmV0d29yayB8fCBuZXR3b3Jrcy5iaXRjb2luXG4gIHZhciB1bm1hdGNoZWQgPSBpbnB1dC5zaWduYXR1cmVzLmNvbmNhdCgpXG5cbiAgaW5wdXQuc2lnbmF0dXJlcyA9IGlucHV0LnB1YktleXMubWFwKGZ1bmN0aW9uIChwdWJLZXkpIHtcbiAgICB2YXIga2V5UGFpciA9IEVDUGFpci5mcm9tUHVibGljS2V5QnVmZmVyKHB1YktleSlcbiAgICB2YXIgbWF0Y2hcblxuICAgIC8vIGNoZWNrIGZvciBhIHNpZ25hdHVyZVxuICAgIHVubWF0Y2hlZC5zb21lKGZ1bmN0aW9uIChzaWduYXR1cmUsIGkpIHtcbiAgICAgIC8vIHNraXAgaWYgdW5kZWZpbmVkIHx8IE9QXzBcbiAgICAgIGlmICghc2lnbmF0dXJlKSByZXR1cm4gZmFsc2VcblxuICAgICAgLy8gVE9ETzogYXZvaWQgTyhuKSBoYXNoRm9yU2lnbmF0dXJlXG4gICAgICB2YXIgcGFyc2VkID0gRUNTaWduYXR1cmUucGFyc2VTY3JpcHRTaWduYXR1cmUoc2lnbmF0dXJlKVxuICAgICAgdmFyIGhhc2hcbiAgICAgIHN3aXRjaCAobmV0d29yay5jb2luKSB7XG4gICAgICAgIGNhc2UgY29pbnMuQlNWOlxuICAgICAgICBjYXNlIGNvaW5zLkJDSDpcbiAgICAgICAgICBoYXNoID0gdHJhbnNhY3Rpb24uaGFzaEZvckNhc2hTaWduYXR1cmUodmluLCBpbnB1dC5zaWduU2NyaXB0LCB2YWx1ZSwgcGFyc2VkLmhhc2hUeXBlKVxuICAgICAgICAgIGJyZWFrXG4gICAgICAgIGNhc2UgY29pbnMuQlRHOlxuICAgICAgICAgIGhhc2ggPSB0cmFuc2FjdGlvbi5oYXNoRm9yR29sZFNpZ25hdHVyZSh2aW4sIGlucHV0LnNpZ25TY3JpcHQsIHZhbHVlLCBwYXJzZWQuaGFzaFR5cGUpXG4gICAgICAgICAgYnJlYWtcbiAgICAgICAgY2FzZSBjb2lucy5aRUM6XG4gICAgICAgICAgaWYgKHZhbHVlID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZVxuICAgICAgICAgIH1cbiAgICAgICAgICBoYXNoID0gdHJhbnNhY3Rpb24uaGFzaEZvclpjYXNoU2lnbmF0dXJlKHZpbiwgaW5wdXQuc2lnblNjcmlwdCwgdmFsdWUsIHBhcnNlZC5oYXNoVHlwZSlcbiAgICAgICAgICBicmVha1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgIGlmIChpbnB1dC53aXRuZXNzKSB7XG4gICAgICAgICAgICBoYXNoID0gdHJhbnNhY3Rpb24uaGFzaEZvcldpdG5lc3NWMCh2aW4sIGlucHV0LnNpZ25TY3JpcHQsIHZhbHVlLCBwYXJzZWQuaGFzaFR5cGUpXG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGhhc2ggPSB0cmFuc2FjdGlvbi5oYXNoRm9yU2lnbmF0dXJlKHZpbiwgaW5wdXQuc2lnblNjcmlwdCwgcGFyc2VkLmhhc2hUeXBlKVxuICAgICAgICAgIH1cbiAgICAgICAgICBicmVha1xuICAgICAgfVxuXG4gICAgICAvLyBza2lwIGlmIHNpZ25hdHVyZSBkb2VzIG5vdCBtYXRjaCBwdWJLZXlcbiAgICAgIGlmICgha2V5UGFpci52ZXJpZnkoaGFzaCwgcGFyc2VkLnNpZ25hdHVyZSkpIHJldHVybiBmYWxzZVxuXG4gICAgICAvLyByZW1vdmUgbWF0Y2hlZCBzaWduYXR1cmUgZnJvbSB1bm1hdGNoZWRcbiAgICAgIHVubWF0Y2hlZFtpXSA9IHVuZGVmaW5lZFxuICAgICAgbWF0Y2ggPSBzaWduYXR1cmVcblxuICAgICAgcmV0dXJuIHRydWVcbiAgICB9KVxuXG4gICAgcmV0dXJuIG1hdGNoXG4gIH0pXG59XG5cbmZ1bmN0aW9uIGV4cGFuZE91dHB1dCAoc2NyaXB0LCBzY3JpcHRUeXBlLCBvdXJQdWJLZXkpIHtcbiAgdHlwZWZvcmNlKHR5cGVzLkJ1ZmZlciwgc2NyaXB0KVxuXG4gIHZhciBzY3JpcHRDaHVua3MgPSBic2NyaXB0LmRlY29tcGlsZShzY3JpcHQpXG4gIGlmICghc2NyaXB0VHlwZSkge1xuICAgIHNjcmlwdFR5cGUgPSBidGVtcGxhdGVzLmNsYXNzaWZ5T3V0cHV0KHNjcmlwdClcbiAgfVxuXG4gIHZhciBwdWJLZXlzID0gW11cblxuICBzd2l0Y2ggKHNjcmlwdFR5cGUpIHtcbiAgICAvLyBkb2VzIG91ciBoYXNoMTYwKHB1YktleSkgbWF0Y2ggdGhlIG91dHB1dCBzY3JpcHRzP1xuICAgIGNhc2Ugc2NyaXB0VHlwZXMuUDJQS0g6XG4gICAgICBpZiAoIW91clB1YktleSkgYnJlYWtcblxuICAgICAgdmFyIHBraDEgPSBzY3JpcHRDaHVua3NbMl1cbiAgICAgIHZhciBwa2gyID0gYmNyeXB0by5oYXNoMTYwKG91clB1YktleSlcbiAgICAgIGlmIChwa2gxLmVxdWFscyhwa2gyKSkgcHViS2V5cyA9IFtvdXJQdWJLZXldXG4gICAgICBicmVha1xuXG4gICAgLy8gZG9lcyBvdXIgaGFzaDE2MChwdWJLZXkpIG1hdGNoIHRoZSBvdXRwdXQgc2NyaXB0cz9cbiAgICBjYXNlIHNjcmlwdFR5cGVzLlAyV1BLSDpcbiAgICAgIGlmICghb3VyUHViS2V5KSBicmVha1xuXG4gICAgICB2YXIgd3BraDEgPSBzY3JpcHRDaHVua3NbMV1cbiAgICAgIHZhciB3cGtoMiA9IGJjcnlwdG8uaGFzaDE2MChvdXJQdWJLZXkpXG4gICAgICBpZiAod3BraDEuZXF1YWxzKHdwa2gyKSkgcHViS2V5cyA9IFtvdXJQdWJLZXldXG4gICAgICBicmVha1xuXG4gICAgY2FzZSBzY3JpcHRUeXBlcy5QMlBLOlxuICAgICAgcHViS2V5cyA9IHNjcmlwdENodW5rcy5zbGljZSgwLCAxKVxuICAgICAgYnJlYWtcblxuICAgIGNhc2Ugc2NyaXB0VHlwZXMuTVVMVElTSUc6XG4gICAgICBwdWJLZXlzID0gc2NyaXB0Q2h1bmtzLnNsaWNlKDEsIC0yKVxuICAgICAgYnJlYWtcblxuICAgIGRlZmF1bHQ6IHJldHVybiB7IHNjcmlwdFR5cGU6IHNjcmlwdFR5cGUgfVxuICB9XG5cbiAgcmV0dXJuIHtcbiAgICBwdWJLZXlzOiBwdWJLZXlzLFxuICAgIHNjcmlwdFR5cGU6IHNjcmlwdFR5cGUsXG4gICAgc2lnbmF0dXJlczogcHViS2V5cy5tYXAoZnVuY3Rpb24gKCkgeyByZXR1cm4gdW5kZWZpbmVkIH0pXG4gIH1cbn1cblxuZnVuY3Rpb24gY2hlY2tQMlNISW5wdXQgKGlucHV0LCByZWRlZW1TY3JpcHRIYXNoKSB7XG4gIGlmIChpbnB1dC5wcmV2T3V0VHlwZSkge1xuICAgIGlmIChpbnB1dC5wcmV2T3V0VHlwZSAhPT0gc2NyaXB0VHlwZXMuUDJTSCkgdGhyb3cgbmV3IEVycm9yKCdQcmV2T3V0U2NyaXB0IG11c3QgYmUgUDJTSCcpXG5cbiAgICB2YXIgcHJldk91dFNjcmlwdFNjcmlwdEhhc2ggPSBic2NyaXB0LmRlY29tcGlsZShpbnB1dC5wcmV2T3V0U2NyaXB0KVsxXVxuICAgIGlmICghcHJldk91dFNjcmlwdFNjcmlwdEhhc2guZXF1YWxzKHJlZGVlbVNjcmlwdEhhc2gpKSB0aHJvdyBuZXcgRXJyb3IoJ0luY29uc2lzdGVudCBoYXNoMTYwKFJlZGVlbVNjcmlwdCknKVxuICB9XG59XG5cbmZ1bmN0aW9uIGNoZWNrUDJXU0hJbnB1dCAoaW5wdXQsIHdpdG5lc3NTY3JpcHRIYXNoKSB7XG4gIGlmIChpbnB1dC5wcmV2T3V0VHlwZSkge1xuICAgIGlmIChpbnB1dC5wcmV2T3V0VHlwZSAhPT0gc2NyaXB0VHlwZXMuUDJXU0gpIHRocm93IG5ldyBFcnJvcignUHJldk91dFNjcmlwdCBtdXN0IGJlIFAyV1NIJylcblxuICAgIHZhciBzY3JpcHRIYXNoID0gYnNjcmlwdC5kZWNvbXBpbGUoaW5wdXQucHJldk91dFNjcmlwdClbMV1cbiAgICBpZiAoIXNjcmlwdEhhc2guZXF1YWxzKHdpdG5lc3NTY3JpcHRIYXNoKSkgdGhyb3cgbmV3IEVycm9yKCdJbmNvbnNpc3RlbnQgc2hhMjUoV2l0bmVzc1NjcmlwdCknKVxuICB9XG59XG5cbmZ1bmN0aW9uIHByZXBhcmVJbnB1dCAoaW5wdXQsIGtwUHViS2V5LCByZWRlZW1TY3JpcHQsIHdpdG5lc3NWYWx1ZSwgd2l0bmVzc1NjcmlwdCkge1xuICB2YXIgZXhwYW5kZWRcbiAgdmFyIHByZXZPdXRUeXBlXG4gIHZhciBwcmV2T3V0U2NyaXB0XG5cbiAgdmFyIHAyc2ggPSBmYWxzZVxuICB2YXIgcDJzaFR5cGVcbiAgdmFyIHJlZGVlbVNjcmlwdEhhc2hcblxuICB2YXIgd2l0bmVzcyA9IGZhbHNlXG4gIHZhciBwMndzaCA9IGZhbHNlXG4gIHZhciB3aXRuZXNzVHlwZVxuICB2YXIgd2l0bmVzc1NjcmlwdEhhc2hcblxuICB2YXIgc2lnblR5cGVcbiAgdmFyIHNpZ25TY3JpcHRcblxuICBpZiAocmVkZWVtU2NyaXB0ICYmIHdpdG5lc3NTY3JpcHQpIHtcbiAgICByZWRlZW1TY3JpcHRIYXNoID0gYmNyeXB0by5oYXNoMTYwKHJlZGVlbVNjcmlwdClcbiAgICB3aXRuZXNzU2NyaXB0SGFzaCA9IGJjcnlwdG8uc2hhMjU2KHdpdG5lc3NTY3JpcHQpXG4gICAgY2hlY2tQMlNISW5wdXQoaW5wdXQsIHJlZGVlbVNjcmlwdEhhc2gpXG5cbiAgICBpZiAoIXJlZGVlbVNjcmlwdC5lcXVhbHMoYnRlbXBsYXRlcy53aXRuZXNzU2NyaXB0SGFzaC5vdXRwdXQuZW5jb2RlKHdpdG5lc3NTY3JpcHRIYXNoKSkpIHRocm93IG5ldyBFcnJvcignV2l0bmVzcyBzY3JpcHQgaW5jb25zaXN0ZW50IHdpdGggcmVkZWVtIHNjcmlwdCcpXG5cbiAgICBleHBhbmRlZCA9IGV4cGFuZE91dHB1dCh3aXRuZXNzU2NyaXB0LCB1bmRlZmluZWQsIGtwUHViS2V5KVxuICAgIGlmICghZXhwYW5kZWQucHViS2V5cykgdGhyb3cgbmV3IEVycm9yKCdXaXRuZXNzU2NyaXB0IG5vdCBzdXBwb3J0ZWQgXCInICsgYnNjcmlwdC50b0FTTShyZWRlZW1TY3JpcHQpICsgJ1wiJylcblxuICAgIHByZXZPdXRUeXBlID0gYnRlbXBsYXRlcy50eXBlcy5QMlNIXG4gICAgcHJldk91dFNjcmlwdCA9IGJ0ZW1wbGF0ZXMuc2NyaXB0SGFzaC5vdXRwdXQuZW5jb2RlKHJlZGVlbVNjcmlwdEhhc2gpXG4gICAgcDJzaCA9IHdpdG5lc3MgPSBwMndzaCA9IHRydWVcbiAgICBwMnNoVHlwZSA9IGJ0ZW1wbGF0ZXMudHlwZXMuUDJXU0hcbiAgICBzaWduVHlwZSA9IHdpdG5lc3NUeXBlID0gZXhwYW5kZWQuc2NyaXB0VHlwZVxuICAgIHNpZ25TY3JpcHQgPSB3aXRuZXNzU2NyaXB0XG4gIH0gZWxzZSBpZiAocmVkZWVtU2NyaXB0KSB7XG4gICAgcmVkZWVtU2NyaXB0SGFzaCA9IGJjcnlwdG8uaGFzaDE2MChyZWRlZW1TY3JpcHQpXG4gICAgY2hlY2tQMlNISW5wdXQoaW5wdXQsIHJlZGVlbVNjcmlwdEhhc2gpXG5cbiAgICBleHBhbmRlZCA9IGV4cGFuZE91dHB1dChyZWRlZW1TY3JpcHQsIHVuZGVmaW5lZCwga3BQdWJLZXkpXG4gICAgaWYgKCFleHBhbmRlZC5wdWJLZXlzKSB0aHJvdyBuZXcgRXJyb3IoJ1JlZGVlbVNjcmlwdCBub3Qgc3VwcG9ydGVkIFwiJyArIGJzY3JpcHQudG9BU00ocmVkZWVtU2NyaXB0KSArICdcIicpXG5cbiAgICBwcmV2T3V0VHlwZSA9IGJ0ZW1wbGF0ZXMudHlwZXMuUDJTSFxuICAgIHByZXZPdXRTY3JpcHQgPSBidGVtcGxhdGVzLnNjcmlwdEhhc2gub3V0cHV0LmVuY29kZShyZWRlZW1TY3JpcHRIYXNoKVxuICAgIHAyc2ggPSB0cnVlXG4gICAgc2lnblR5cGUgPSBwMnNoVHlwZSA9IGV4cGFuZGVkLnNjcmlwdFR5cGVcbiAgICBzaWduU2NyaXB0ID0gcmVkZWVtU2NyaXB0XG4gICAgd2l0bmVzcyA9IHNpZ25UeXBlID09PSBidGVtcGxhdGVzLnR5cGVzLlAyV1BLSFxuICB9IGVsc2UgaWYgKHdpdG5lc3NTY3JpcHQpIHtcbiAgICB3aXRuZXNzU2NyaXB0SGFzaCA9IGJjcnlwdG8uc2hhMjU2KHdpdG5lc3NTY3JpcHQpXG4gICAgY2hlY2tQMldTSElucHV0KGlucHV0LCB3aXRuZXNzU2NyaXB0SGFzaClcblxuICAgIGV4cGFuZGVkID0gZXhwYW5kT3V0cHV0KHdpdG5lc3NTY3JpcHQsIHVuZGVmaW5lZCwga3BQdWJLZXkpXG4gICAgaWYgKCFleHBhbmRlZC5wdWJLZXlzKSB0aHJvdyBuZXcgRXJyb3IoJ1dpdG5lc3NTY3JpcHQgbm90IHN1cHBvcnRlZCBcIicgKyBic2NyaXB0LnRvQVNNKHJlZGVlbVNjcmlwdCkgKyAnXCInKVxuXG4gICAgcHJldk91dFR5cGUgPSBidGVtcGxhdGVzLnR5cGVzLlAyV1NIXG4gICAgcHJldk91dFNjcmlwdCA9IGJ0ZW1wbGF0ZXMud2l0bmVzc1NjcmlwdEhhc2gub3V0cHV0LmVuY29kZSh3aXRuZXNzU2NyaXB0SGFzaClcbiAgICB3aXRuZXNzID0gcDJ3c2ggPSB0cnVlXG4gICAgc2lnblR5cGUgPSB3aXRuZXNzVHlwZSA9IGV4cGFuZGVkLnNjcmlwdFR5cGVcbiAgICBzaWduU2NyaXB0ID0gd2l0bmVzc1NjcmlwdFxuICB9IGVsc2UgaWYgKGlucHV0LnByZXZPdXRUeXBlKSB7XG4gICAgLy8gZW1iZWRkZWQgc2NyaXB0cyBhcmUgbm90IHBvc3NpYmxlIHdpdGhvdXQgYSByZWRlZW1TY3JpcHRcbiAgICBpZiAoaW5wdXQucHJldk91dFR5cGUgPT09IHNjcmlwdFR5cGVzLlAyU0ggfHxcbiAgICAgIGlucHV0LnByZXZPdXRUeXBlID09PSBzY3JpcHRUeXBlcy5QMldTSCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdQcmV2T3V0U2NyaXB0IGlzICcgKyBpbnB1dC5wcmV2T3V0VHlwZSArICcsIHJlcXVpcmVzIHJlZGVlbVNjcmlwdCcpXG4gICAgfVxuXG4gICAgcHJldk91dFR5cGUgPSBpbnB1dC5wcmV2T3V0VHlwZVxuICAgIHByZXZPdXRTY3JpcHQgPSBpbnB1dC5wcmV2T3V0U2NyaXB0XG4gICAgZXhwYW5kZWQgPSBleHBhbmRPdXRwdXQoaW5wdXQucHJldk91dFNjcmlwdCwgaW5wdXQucHJldk91dFR5cGUsIGtwUHViS2V5KVxuICAgIGlmICghZXhwYW5kZWQucHViS2V5cykgcmV0dXJuXG5cbiAgICB3aXRuZXNzID0gKGlucHV0LnByZXZPdXRUeXBlID09PSBzY3JpcHRUeXBlcy5QMldQS0gpXG4gICAgc2lnblR5cGUgPSBwcmV2T3V0VHlwZVxuICAgIHNpZ25TY3JpcHQgPSBwcmV2T3V0U2NyaXB0XG4gIH0gZWxzZSB7XG4gICAgcHJldk91dFNjcmlwdCA9IGJ0ZW1wbGF0ZXMucHViS2V5SGFzaC5vdXRwdXQuZW5jb2RlKGJjcnlwdG8uaGFzaDE2MChrcFB1YktleSkpXG4gICAgZXhwYW5kZWQgPSBleHBhbmRPdXRwdXQocHJldk91dFNjcmlwdCwgc2NyaXB0VHlwZXMuUDJQS0gsIGtwUHViS2V5KVxuXG4gICAgcHJldk91dFR5cGUgPSBzY3JpcHRUeXBlcy5QMlBLSFxuICAgIHdpdG5lc3MgPSBmYWxzZVxuICAgIHNpZ25UeXBlID0gcHJldk91dFR5cGVcbiAgICBzaWduU2NyaXB0ID0gcHJldk91dFNjcmlwdFxuICB9XG5cbiAgaWYgKHNpZ25UeXBlID09PSBzY3JpcHRUeXBlcy5QMldQS0gpIHtcbiAgICBzaWduU2NyaXB0ID0gYnRlbXBsYXRlcy5wdWJLZXlIYXNoLm91dHB1dC5lbmNvZGUoYnRlbXBsYXRlcy53aXRuZXNzUHViS2V5SGFzaC5vdXRwdXQuZGVjb2RlKHNpZ25TY3JpcHQpKVxuICB9XG5cbiAgaWYgKHAyc2gpIHtcbiAgICBpbnB1dC5yZWRlZW1TY3JpcHQgPSByZWRlZW1TY3JpcHRcbiAgICBpbnB1dC5yZWRlZW1TY3JpcHRUeXBlID0gcDJzaFR5cGVcbiAgfVxuXG4gIGlmIChwMndzaCkge1xuICAgIGlucHV0LndpdG5lc3NTY3JpcHQgPSB3aXRuZXNzU2NyaXB0XG4gICAgaW5wdXQud2l0bmVzc1NjcmlwdFR5cGUgPSB3aXRuZXNzVHlwZVxuICB9XG5cbiAgaW5wdXQucHViS2V5cyA9IGV4cGFuZGVkLnB1YktleXNcbiAgaW5wdXQuc2lnbmF0dXJlcyA9IGV4cGFuZGVkLnNpZ25hdHVyZXNcbiAgaW5wdXQuc2lnblNjcmlwdCA9IHNpZ25TY3JpcHRcbiAgaW5wdXQuc2lnblR5cGUgPSBzaWduVHlwZVxuICBpbnB1dC5wcmV2T3V0U2NyaXB0ID0gcHJldk91dFNjcmlwdFxuICBpbnB1dC5wcmV2T3V0VHlwZSA9IHByZXZPdXRUeXBlXG4gIGlucHV0LndpdG5lc3MgPSB3aXRuZXNzXG59XG5cbmZ1bmN0aW9uIGJ1aWxkU3RhY2sgKHR5cGUsIHNpZ25hdHVyZXMsIHB1YktleXMsIGFsbG93SW5jb21wbGV0ZSkge1xuICBpZiAodHlwZSA9PT0gc2NyaXB0VHlwZXMuUDJQS0gpIHtcbiAgICBpZiAoc2lnbmF0dXJlcy5sZW5ndGggPT09IDEgJiYgQnVmZmVyLmlzQnVmZmVyKHNpZ25hdHVyZXNbMF0pICYmIHB1YktleXMubGVuZ3RoID09PSAxKSByZXR1cm4gYnRlbXBsYXRlcy5wdWJLZXlIYXNoLmlucHV0LmVuY29kZVN0YWNrKHNpZ25hdHVyZXNbMF0sIHB1YktleXNbMF0pXG4gIH0gZWxzZSBpZiAodHlwZSA9PT0gc2NyaXB0VHlwZXMuUDJQSykge1xuICAgIGlmIChzaWduYXR1cmVzLmxlbmd0aCA9PT0gMSAmJiBCdWZmZXIuaXNCdWZmZXIoc2lnbmF0dXJlc1swXSkpIHJldHVybiBidGVtcGxhdGVzLnB1YktleS5pbnB1dC5lbmNvZGVTdGFjayhzaWduYXR1cmVzWzBdKVxuICB9IGVsc2UgaWYgKHR5cGUgPT09IHNjcmlwdFR5cGVzLk1VTFRJU0lHKSB7XG4gICAgaWYgKHNpZ25hdHVyZXMubGVuZ3RoID4gMCkge1xuICAgICAgc2lnbmF0dXJlcyA9IHNpZ25hdHVyZXMubWFwKGZ1bmN0aW9uIChzaWduYXR1cmUpIHtcbiAgICAgICAgcmV0dXJuIHNpZ25hdHVyZSB8fCBvcHMuT1BfMFxuICAgICAgfSlcbiAgICAgIGlmICghYWxsb3dJbmNvbXBsZXRlKSB7XG4gICAgICAgIC8vIHJlbW92ZSBibGFuayBzaWduYXR1cmVzXG4gICAgICAgIHNpZ25hdHVyZXMgPSBzaWduYXR1cmVzLmZpbHRlcihmdW5jdGlvbiAoeCkgeyByZXR1cm4geCAhPT0gb3BzLk9QXzAgfSlcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGJ0ZW1wbGF0ZXMubXVsdGlzaWcuaW5wdXQuZW5jb2RlU3RhY2soc2lnbmF0dXJlcylcbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdOb3QgeWV0IHN1cHBvcnRlZCcpXG4gIH1cblxuICBpZiAoIWFsbG93SW5jb21wbGV0ZSkgdGhyb3cgbmV3IEVycm9yKCdOb3QgZW5vdWdoIHNpZ25hdHVyZXMgcHJvdmlkZWQnKVxuICByZXR1cm4gW11cbn1cblxuZnVuY3Rpb24gYnVpbGRJbnB1dCAoaW5wdXQsIGFsbG93SW5jb21wbGV0ZSkge1xuICB2YXIgc2NyaXB0VHlwZSA9IGlucHV0LnByZXZPdXRUeXBlXG4gIHZhciBzaWcgPSBbXVxuICB2YXIgd2l0bmVzcyA9IFtdXG5cbiAgaWYgKHN1cHBvcnRlZFR5cGUoc2NyaXB0VHlwZSkpIHtcbiAgICBzaWcgPSBidWlsZFN0YWNrKHNjcmlwdFR5cGUsIGlucHV0LnNpZ25hdHVyZXMsIGlucHV0LnB1YktleXMsIGFsbG93SW5jb21wbGV0ZSlcbiAgfVxuXG4gIHZhciBwMnNoID0gZmFsc2VcbiAgaWYgKHNjcmlwdFR5cGUgPT09IGJ0ZW1wbGF0ZXMudHlwZXMuUDJTSCkge1xuICAgIC8vIFdlIGNhbiByZW1vdmUgdGhpcyBlcnJvciBsYXRlciB3aGVuIHdlIGhhdmUgYSBndWFyYW50ZWUgcHJlcGFyZUlucHV0XG4gICAgLy8gcmVqZWN0cyB1bnNpZ25hYmxlIHNjcmlwdHMgLSBpdCBNVVNUIGJlIHNpZ25hYmxlIGF0IHRoaXMgcG9pbnQuXG4gICAgaWYgKCFhbGxvd0luY29tcGxldGUgJiYgIXN1cHBvcnRlZFAyU0hUeXBlKGlucHV0LnJlZGVlbVNjcmlwdFR5cGUpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ltcG9zc2libGUgdG8gc2lnbiB0aGlzIHR5cGUnKVxuICAgIH1cblxuICAgIGlmIChzdXBwb3J0ZWRUeXBlKGlucHV0LnJlZGVlbVNjcmlwdFR5cGUpKSB7XG4gICAgICBzaWcgPSBidWlsZFN0YWNrKGlucHV0LnJlZGVlbVNjcmlwdFR5cGUsIGlucHV0LnNpZ25hdHVyZXMsIGlucHV0LnB1YktleXMsIGFsbG93SW5jb21wbGV0ZSlcbiAgICB9XG5cbiAgICAvLyBJZiBpdCB3YXNuJ3QgU0lHTkFCTEUsIGl0J3Mgd2l0bmVzcywgZGVmZXIgdG8gdGhhdFxuICAgIGlmIChpbnB1dC5yZWRlZW1TY3JpcHRUeXBlKSB7XG4gICAgICBwMnNoID0gdHJ1ZVxuICAgICAgc2NyaXB0VHlwZSA9IGlucHV0LnJlZGVlbVNjcmlwdFR5cGVcbiAgICB9XG4gIH1cblxuICBzd2l0Y2ggKHNjcmlwdFR5cGUpIHtcbiAgICAvLyBQMldQS0ggaXMgYSBzcGVjaWFsIGNhc2Ugb2YgUDJQS0hcbiAgICBjYXNlIGJ0ZW1wbGF0ZXMudHlwZXMuUDJXUEtIOlxuICAgICAgd2l0bmVzcyA9IGJ1aWxkU3RhY2soYnRlbXBsYXRlcy50eXBlcy5QMlBLSCwgaW5wdXQuc2lnbmF0dXJlcywgaW5wdXQucHViS2V5cywgYWxsb3dJbmNvbXBsZXRlKVxuICAgICAgYnJlYWtcblxuICAgIGNhc2UgYnRlbXBsYXRlcy50eXBlcy5QMldTSDpcbiAgICAgIC8vIFdlIGNhbiByZW1vdmUgdGhpcyBjaGVjayBsYXRlclxuICAgICAgaWYgKCFhbGxvd0luY29tcGxldGUgJiYgIXN1cHBvcnRlZFR5cGUoaW5wdXQud2l0bmVzc1NjcmlwdFR5cGUpKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignSW1wb3NzaWJsZSB0byBzaWduIHRoaXMgdHlwZScpXG4gICAgICB9XG5cbiAgICAgIGlmIChzdXBwb3J0ZWRUeXBlKGlucHV0LndpdG5lc3NTY3JpcHRUeXBlKSkge1xuICAgICAgICB3aXRuZXNzID0gYnVpbGRTdGFjayhpbnB1dC53aXRuZXNzU2NyaXB0VHlwZSwgaW5wdXQuc2lnbmF0dXJlcywgaW5wdXQucHViS2V5cywgYWxsb3dJbmNvbXBsZXRlKVxuICAgICAgICB3aXRuZXNzLnB1c2goaW5wdXQud2l0bmVzc1NjcmlwdClcbiAgICAgICAgc2NyaXB0VHlwZSA9IGlucHV0LndpdG5lc3NTY3JpcHRUeXBlXG4gICAgICB9XG4gICAgICBicmVha1xuICB9XG5cbiAgLy8gYXBwZW5kIHJlZGVlbVNjcmlwdCBpZiBuZWNlc3NhcnlcbiAgaWYgKHAyc2gpIHtcbiAgICBzaWcucHVzaChpbnB1dC5yZWRlZW1TY3JpcHQpXG4gIH1cblxuICByZXR1cm4ge1xuICAgIHR5cGU6IHNjcmlwdFR5cGUsXG4gICAgc2NyaXB0OiBic2NyaXB0LmNvbXBpbGUoc2lnKSxcbiAgICB3aXRuZXNzOiB3aXRuZXNzXG4gIH1cbn1cblxuLy8gQnkgZGVmYXVsdCwgYXNzdW1lIGlzIGEgYml0Y29pbiB0cmFuc2FjdGlvblxuZnVuY3Rpb24gVHJhbnNhY3Rpb25CdWlsZGVyIChuZXR3b3JrLCBtYXhpbXVtRmVlUmF0ZSkge1xuICB0aGlzLnByZXZUeE1hcCA9IHt9XG4gIHRoaXMubmV0d29yayA9IG5ldHdvcmsgfHwgbmV0d29ya3MuYml0Y29pblxuXG4gIC8vIFdBUk5JTkc6IFRoaXMgaXMgX19OT1RfXyB0byBiZSByZWxpZWQgb24sIGl0cyBqdXN0IGFub3RoZXIgcG90ZW50aWFsIHNhZmV0eSBtZWNoYW5pc20gKHNhZmV0eSBpbi1kZXB0aClcbiAgdGhpcy5tYXhpbXVtRmVlUmF0ZSA9IG1heGltdW1GZWVSYXRlIHx8IDI1MDBcblxuICB0aGlzLmlucHV0cyA9IFtdXG4gIHRoaXMudHggPSBuZXcgVHJhbnNhY3Rpb24odGhpcy5uZXR3b3JrKVxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLnNldExvY2tUaW1lID0gZnVuY3Rpb24gKGxvY2t0aW1lKSB7XG4gIHR5cGVmb3JjZSh0eXBlcy5VSW50MzIsIGxvY2t0aW1lKVxuXG4gIC8vIGlmIGFueSBzaWduYXR1cmVzIGV4aXN0LCB0aHJvd1xuICBpZiAodGhpcy5pbnB1dHMuc29tZShmdW5jdGlvbiAoaW5wdXQpIHtcbiAgICBpZiAoIWlucHV0LnNpZ25hdHVyZXMpIHJldHVybiBmYWxzZVxuXG4gICAgcmV0dXJuIGlucHV0LnNpZ25hdHVyZXMuc29tZShmdW5jdGlvbiAocykgeyByZXR1cm4gcyB9KVxuICB9KSkge1xuICAgIHRocm93IG5ldyBFcnJvcignTm8sIHRoaXMgd291bGQgaW52YWxpZGF0ZSBzaWduYXR1cmVzJylcbiAgfVxuXG4gIHRoaXMudHgubG9ja3RpbWUgPSBsb2NrdGltZVxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLnNldFZlcnNpb24gPSBmdW5jdGlvbiAodmVyc2lvbiwgb3ZlcndpbnRlciA9IHRydWUpIHtcbiAgdHlwZWZvcmNlKHR5cGVzLlVJbnQzMiwgdmVyc2lvbilcblxuICBpZiAoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspKSB7XG4gICAgaWYgKCF0aGlzLm5ldHdvcmsuY29uc2Vuc3VzQnJhbmNoSWQuaGFzT3duUHJvcGVydHkodGhpcy50eC52ZXJzaW9uKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdVbnN1cHBvcnRlZCBaY2FzaCB0cmFuc2FjdGlvbicpXG4gICAgfVxuICAgIHRoaXMudHgub3ZlcndpbnRlcmVkID0gKG92ZXJ3aW50ZXIgPyAxIDogMClcbiAgICB0aGlzLnR4LmNvbnNlbnN1c0JyYW5jaElkID0gdGhpcy5uZXR3b3JrLmNvbnNlbnN1c0JyYW5jaElkW3ZlcnNpb25dXG4gIH1cbiAgdGhpcy50eC52ZXJzaW9uID0gdmVyc2lvblxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLnNldENvbnNlbnN1c0JyYW5jaElkID0gZnVuY3Rpb24gKGNvbnNlbnN1c0JyYW5jaElkKSB7XG4gIGlmICghY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdjb25zZW5zdXNCcmFuY2hJZCBjYW4gb25seSBiZSBzZXQgZm9yIFpjYXNoIHRyYW5zYWN0aW9ucycpXG4gIH1cbiAgaWYgKCF0aGlzLmlucHV0cy5ldmVyeShmdW5jdGlvbiAoaW5wdXQpIHsgcmV0dXJuIGlucHV0LnNpZ25hdHVyZXMgPT09IHVuZGVmaW5lZCB9KSkge1xuICAgIHRocm93IG5ldyBFcnJvcignQ2hhbmdpbmcgdGhlIGNvbnNlbnN1c0JyYW5jaElkIGZvciBhIHBhcnRpYWxseSBzaWduZWQgdHJhbnNhY3Rpb24gd291bGQgaW52YWxpZGF0ZSBzaWduYXR1cmVzJylcbiAgfVxuICB0eXBlZm9yY2UodHlwZXMuVUludDMyLCBjb25zZW5zdXNCcmFuY2hJZClcbiAgdGhpcy50eC5jb25zZW5zdXNCcmFuY2hJZCA9IGNvbnNlbnN1c0JyYW5jaElkXG59XG5cblRyYW5zYWN0aW9uQnVpbGRlci5wcm90b3R5cGUuc2V0VmVyc2lvbkdyb3VwSWQgPSBmdW5jdGlvbiAodmVyc2lvbkdyb3VwSWQpIHtcbiAgaWYgKCEoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspICYmIHRoaXMudHguaXNPdmVyd2ludGVyQ29tcGF0aWJsZSgpKSkge1xuICAgIHRocm93IG5ldyBFcnJvcignZXhwaXJ5SGVpZ2h0IGNhbiBvbmx5IGJlIHNldCBmb3IgWmNhc2ggc3RhcnRpbmcgYXQgb3ZlcndpbnRlciB2ZXJzaW9uLiBDdXJyZW50IG5ldHdvcmsgY29pbjogJyArXG4gICAgICB0aGlzLm5ldHdvcmsuY29pbiArICcsIHZlcnNpb246ICcgKyB0aGlzLnR4LnZlcnNpb24pXG4gIH1cbiAgdHlwZWZvcmNlKHR5cGVzLlVJbnQzMiwgdmVyc2lvbkdyb3VwSWQpXG4gIHRoaXMudHgudmVyc2lvbkdyb3VwSWQgPSB2ZXJzaW9uR3JvdXBJZFxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLnNldEV4cGlyeUhlaWdodCA9IGZ1bmN0aW9uIChleHBpcnlIZWlnaHQpIHtcbiAgaWYgKCEoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspICYmIHRoaXMudHguaXNPdmVyd2ludGVyQ29tcGF0aWJsZSgpKSkge1xuICAgIHRocm93IG5ldyBFcnJvcignZXhwaXJ5SGVpZ2h0IGNhbiBvbmx5IGJlIHNldCBmb3IgWmNhc2ggc3RhcnRpbmcgYXQgb3ZlcndpbnRlciB2ZXJzaW9uLiBDdXJyZW50IG5ldHdvcmsgY29pbjogJyArXG4gICAgICB0aGlzLm5ldHdvcmsuY29pbiArICcsIHZlcnNpb246ICcgKyB0aGlzLnR4LnZlcnNpb24pXG4gIH1cbiAgdHlwZWZvcmNlKHR5cGVzLlVJbnQzMiwgZXhwaXJ5SGVpZ2h0KVxuICB0aGlzLnR4LmV4cGlyeUhlaWdodCA9IGV4cGlyeUhlaWdodFxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLnNldEpvaW5TcGxpdHMgPSBmdW5jdGlvbiAodHJhbnNhY3Rpb24pIHtcbiAgaWYgKCEoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspICYmIHRoaXMudHguc3VwcG9ydHNKb2luU3BsaXRzKCkpKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdqb2luc3BsaXRzIGNhbiBvbmx5IGJlIHNldCBmb3IgWmNhc2ggc3RhcnRpbmcgYXQgdmVyc2lvbiAyLiBDdXJyZW50IG5ldHdvcmsgY29pbjogJyArXG4gICAgICB0aGlzLm5ldHdvcmsuY29pbiArICcsIHZlcnNpb246ICcgKyB0aGlzLnR4LnZlcnNpb24pXG4gIH1cbiAgaWYgKHRyYW5zYWN0aW9uICYmIHRyYW5zYWN0aW9uLmpvaW5zcGxpdHMpIHtcbiAgICB0aGlzLnR4LmpvaW5zcGxpdHMgPSB0cmFuc2FjdGlvbi5qb2luc3BsaXRzLm1hcChmdW5jdGlvbiAodHhKb2luc3BsaXQpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHZwdWJPbGQ6IHR4Sm9pbnNwbGl0LnZwdWJPbGQsXG4gICAgICAgIHZwdWJOZXc6IHR4Sm9pbnNwbGl0LnZwdWJOZXcsXG4gICAgICAgIGFuY2hvcjogdHhKb2luc3BsaXQuYW5jaG9yLFxuICAgICAgICBudWxsaWZpZXJzOiB0eEpvaW5zcGxpdC5udWxsaWZpZXJzLFxuICAgICAgICBjb21taXRtZW50czogdHhKb2luc3BsaXQuY29tbWl0bWVudHMsXG4gICAgICAgIGVwaGVtZXJhbEtleTogdHhKb2luc3BsaXQuZXBoZW1lcmFsS2V5LFxuICAgICAgICByYW5kb21TZWVkOiB0eEpvaW5zcGxpdC5yYW5kb21TZWVkLFxuICAgICAgICBtYWNzOiB0eEpvaW5zcGxpdC5tYWNzLFxuICAgICAgICB6cHJvb2Y6IHR4Sm9pbnNwbGl0Lnpwcm9vZixcbiAgICAgICAgY2lwaGVydGV4dHM6IHR4Sm9pbnNwbGl0LmNpcGhlcnRleHRzXG4gICAgICB9XG4gICAgfSlcblxuICAgIHRoaXMudHguam9pbnNwbGl0UHVia2V5ID0gdHJhbnNhY3Rpb24uam9pbnNwbGl0UHVia2V5XG4gICAgdGhpcy50eC5qb2luc3BsaXRTaWcgPSB0cmFuc2FjdGlvbi5qb2luc3BsaXRTaWdcbiAgICByZXR1cm5cbiAgfVxuICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgdHJhbnNhY3Rpb24gd2l0aCBqb2luc3BsaXRzJylcbn1cblxuVHJhbnNhY3Rpb25CdWlsZGVyLmZyb21UcmFuc2FjdGlvbiA9IGZ1bmN0aW9uICh0cmFuc2FjdGlvbiwgbmV0d29yaykge1xuICB2YXIgdHhiTmV0d29yayA9IG5ldHdvcmsgfHwgbmV0d29ya3MuYml0Y29pblxuICB2YXIgdHhiID0gbmV3IFRyYW5zYWN0aW9uQnVpbGRlcih0eGJOZXR3b3JrKVxuXG4gIGlmICh0eGIubmV0d29yay5jb2luICE9PSB0cmFuc2FjdGlvbi5uZXR3b3JrLmNvaW4pIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ1RoaXMgdHJhbnNhY3Rpb24gaXMgaW5jb21wYXRpYmxlIHdpdGggdGhlIHRyYW5zYWN0aW9uIGJ1aWxkZXInKVxuICB9XG5cbiAgLy8gQ29weSB0cmFuc2FjdGlvbiBmaWVsZHNcbiAgdHhiLnNldFZlcnNpb24odHJhbnNhY3Rpb24udmVyc2lvbiwgdHJhbnNhY3Rpb24ub3ZlcndpbnRlcmVkKVxuICB0eGIuc2V0TG9ja1RpbWUodHJhbnNhY3Rpb24ubG9ja3RpbWUpXG5cbiAgaWYgKGNvaW5zLmlzWmNhc2godHhiTmV0d29yaykpIHtcbiAgICAvLyBDb3B5IFpjYXNoIG92ZXJ3aW50ZXIgZmllbGRzLiBPbWl0dGVkIGlmIHRoZSB0cmFuc2FjdGlvbiBidWlsZGVyIGlzIG5vdCBmb3IgWmNhc2guXG4gICAgaWYgKHR4Yi50eC5pc092ZXJ3aW50ZXJDb21wYXRpYmxlKCkpIHtcbiAgICAgIHR4Yi5zZXRWZXJzaW9uR3JvdXBJZCh0cmFuc2FjdGlvbi52ZXJzaW9uR3JvdXBJZClcbiAgICAgIHR4Yi5zZXRFeHBpcnlIZWlnaHQodHJhbnNhY3Rpb24uZXhwaXJ5SGVpZ2h0KVxuICAgIH1cblxuICAgIC8vIFdlIGRvbid0IHN1cHBvcnQgcHJvdGVjdGVkIHRyYW5zYWN0aW9ucyBidXQgd2UgY29weSB0aGUgam9pbnNwbGl0cyBmb3IgY29uc2lzdGVuY3kuIEhvd2V2ZXIsIHRoZSB0cmFuc2FjdGlvblxuICAgIC8vIGJ1aWxkZXIgd2lsbCBmYWlsIHdoZW4gd2UgdHJ5IHRvIHNpZ24gb25lIG9mIHRoZXNlIHRyYW5zYWN0aW9uc1xuICAgIGlmICh0eGIudHguc3VwcG9ydHNKb2luU3BsaXRzKCkpIHtcbiAgICAgIHR4Yi5zZXRKb2luU3BsaXRzKHRyYW5zYWN0aW9uKVxuICAgIH1cbiAgICB0eGIuc2V0Q29uc2Vuc3VzQnJhbmNoSWQodHJhbnNhY3Rpb24uY29uc2Vuc3VzQnJhbmNoSWQpXG4gIH1cblxuICAvLyBDb3B5IERhc2ggc3BlY2lhbCB0cmFuc2FjdGlvbiBmaWVsZHMuIE9taXR0ZWQgaWYgdGhlIHRyYW5zYWN0aW9uIGJ1aWxkZXIgaXMgbm90IGZvciBEYXNoLlxuICBpZiAoY29pbnMuaXNEYXNoKHR4Yk5ldHdvcmspKSB7XG4gICAgdHlwZWZvcmNlKHR5cGVzLlVJbnQxNiwgdHJhbnNhY3Rpb24udHlwZSlcbiAgICB0eGIudHgudHlwZSA9IHRyYW5zYWN0aW9uLnR5cGVcblxuICAgIGlmICh0eGIudHgudmVyc2lvblN1cHBvcnRzRGFzaFNwZWNpYWxUcmFuc2FjdGlvbnMoKSkge1xuICAgICAgdHlwZWZvcmNlKHR5cGVzLkJ1ZmZlciwgdHJhbnNhY3Rpb24uZXh0cmFQYXlsb2FkKVxuICAgICAgdHhiLnR4LmV4dHJhUGF5bG9hZCA9IHRyYW5zYWN0aW9uLmV4dHJhUGF5bG9hZFxuICAgIH1cbiAgfVxuXG4gIC8vIENvcHkgb3V0cHV0cyAoZG9uZSBmaXJzdCB0byBhdm9pZCBzaWduYXR1cmUgaW52YWxpZGF0aW9uKVxuICB0cmFuc2FjdGlvbi5vdXRzLmZvckVhY2goZnVuY3Rpb24gKHR4T3V0KSB7XG4gICAgdHhiLmFkZE91dHB1dCh0eE91dC5zY3JpcHQsIHR4T3V0LnZhbHVlKVxuICB9KVxuXG4gIC8vIENvcHkgaW5wdXRzXG4gIHRyYW5zYWN0aW9uLmlucy5mb3JFYWNoKGZ1bmN0aW9uICh0eEluKSB7XG4gICAgdHhiLl9fYWRkSW5wdXRVbnNhZmUodHhJbi5oYXNoLCB0eEluLmluZGV4LCB7XG4gICAgICBzZXF1ZW5jZTogdHhJbi5zZXF1ZW5jZSxcbiAgICAgIHNjcmlwdDogdHhJbi5zY3JpcHQsXG4gICAgICB3aXRuZXNzOiB0eEluLndpdG5lc3MsXG4gICAgICB2YWx1ZTogdHhJbi52YWx1ZVxuICAgIH0pXG4gIH0pXG5cbiAgLy8gZml4IHNvbWUgdGhpbmdzIG5vdCBwb3NzaWJsZSB0aHJvdWdoIHRoZSBwdWJsaWMgQVBJXG4gIHR4Yi5pbnB1dHMuZm9yRWFjaChmdW5jdGlvbiAoaW5wdXQsIGkpIHtcbiAgICBmaXhNdWx0aXNpZ09yZGVyKGlucHV0LCB0cmFuc2FjdGlvbiwgaSwgaW5wdXQudmFsdWUsIHR4Yk5ldHdvcmspXG4gIH0pXG5cbiAgcmV0dXJuIHR4YlxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLmFkZElucHV0ID0gZnVuY3Rpb24gKHR4SGFzaCwgdm91dCwgc2VxdWVuY2UsIHByZXZPdXRTY3JpcHQpIHtcbiAgaWYgKCF0aGlzLl9fY2FuTW9kaWZ5SW5wdXRzKCkpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ05vLCB0aGlzIHdvdWxkIGludmFsaWRhdGUgc2lnbmF0dXJlcycpXG4gIH1cblxuICB2YXIgdmFsdWVcblxuICAvLyBpcyBpdCBhIGhleCBzdHJpbmc/XG4gIGlmICh0eXBlb2YgdHhIYXNoID09PSAnc3RyaW5nJykge1xuICAgIC8vIHRyYW5zYWN0aW9uIGhhc2hzJ3MgYXJlIGRpc3BsYXllZCBpbiByZXZlcnNlIG9yZGVyLCB1bi1yZXZlcnNlIGl0XG4gICAgdHhIYXNoID0gQnVmZmVyLmZyb20odHhIYXNoLCAnaGV4JykucmV2ZXJzZSgpXG5cbiAgLy8gaXMgaXQgYSBUcmFuc2FjdGlvbiBvYmplY3Q/XG4gIH0gZWxzZSBpZiAodHhIYXNoIGluc3RhbmNlb2YgVHJhbnNhY3Rpb24pIHtcbiAgICB2YXIgdHhPdXQgPSB0eEhhc2gub3V0c1t2b3V0XVxuICAgIHByZXZPdXRTY3JpcHQgPSB0eE91dC5zY3JpcHRcbiAgICB2YWx1ZSA9IHR4T3V0LnZhbHVlXG5cbiAgICB0eEhhc2ggPSB0eEhhc2guZ2V0SGFzaCgpXG4gIH1cblxuICByZXR1cm4gdGhpcy5fX2FkZElucHV0VW5zYWZlKHR4SGFzaCwgdm91dCwge1xuICAgIHNlcXVlbmNlOiBzZXF1ZW5jZSxcbiAgICBwcmV2T3V0U2NyaXB0OiBwcmV2T3V0U2NyaXB0LFxuICAgIHZhbHVlOiB2YWx1ZVxuICB9KVxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLl9fYWRkSW5wdXRVbnNhZmUgPSBmdW5jdGlvbiAodHhIYXNoLCB2b3V0LCBvcHRpb25zKSB7XG4gIGlmIChUcmFuc2FjdGlvbi5pc0NvaW5iYXNlSGFzaCh0eEhhc2gpKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdjb2luYmFzZSBpbnB1dHMgbm90IHN1cHBvcnRlZCcpXG4gIH1cblxuICB2YXIgcHJldlR4T3V0ID0gdHhIYXNoLnRvU3RyaW5nKCdoZXgnKSArICc6JyArIHZvdXRcbiAgaWYgKHRoaXMucHJldlR4TWFwW3ByZXZUeE91dF0gIT09IHVuZGVmaW5lZCkgdGhyb3cgbmV3IEVycm9yKCdEdXBsaWNhdGUgVHhPdXQ6ICcgKyBwcmV2VHhPdXQpXG5cbiAgdmFyIGlucHV0ID0ge31cblxuICAvLyBkZXJpdmUgd2hhdCB3ZSBjYW4gZnJvbSB0aGUgc2NyaXB0U2lnXG4gIGlmIChvcHRpb25zLnNjcmlwdCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgaW5wdXQgPSBleHBhbmRJbnB1dChvcHRpb25zLnNjcmlwdCwgb3B0aW9ucy53aXRuZXNzIHx8IFtdKVxuICB9XG5cbiAgLy8gaWYgYW4gaW5wdXQgdmFsdWUgd2FzIGdpdmVuLCByZXRhaW4gaXRcbiAgaWYgKG9wdGlvbnMudmFsdWUgIT09IHVuZGVmaW5lZCkge1xuICAgIGlucHV0LnZhbHVlID0gb3B0aW9ucy52YWx1ZVxuICB9XG5cbiAgLy8gZGVyaXZlIHdoYXQgd2UgY2FuIGZyb20gdGhlIHByZXZpb3VzIHRyYW5zYWN0aW9ucyBvdXRwdXQgc2NyaXB0XG4gIGlmICghaW5wdXQucHJldk91dFNjcmlwdCAmJiBvcHRpb25zLnByZXZPdXRTY3JpcHQpIHtcbiAgICB2YXIgcHJldk91dFR5cGVcblxuICAgIGlmICghaW5wdXQucHViS2V5cyAmJiAhaW5wdXQuc2lnbmF0dXJlcykge1xuICAgICAgdmFyIGV4cGFuZGVkID0gZXhwYW5kT3V0cHV0KG9wdGlvbnMucHJldk91dFNjcmlwdClcblxuICAgICAgaWYgKGV4cGFuZGVkLnB1YktleXMpIHtcbiAgICAgICAgaW5wdXQucHViS2V5cyA9IGV4cGFuZGVkLnB1YktleXNcbiAgICAgICAgaW5wdXQuc2lnbmF0dXJlcyA9IGV4cGFuZGVkLnNpZ25hdHVyZXNcbiAgICAgIH1cblxuICAgICAgcHJldk91dFR5cGUgPSBleHBhbmRlZC5zY3JpcHRUeXBlXG4gICAgfVxuXG4gICAgaW5wdXQucHJldk91dFNjcmlwdCA9IG9wdGlvbnMucHJldk91dFNjcmlwdFxuICAgIGlucHV0LnByZXZPdXRUeXBlID0gcHJldk91dFR5cGUgfHwgYnRlbXBsYXRlcy5jbGFzc2lmeU91dHB1dChvcHRpb25zLnByZXZPdXRTY3JpcHQpXG4gIH1cblxuICB2YXIgdmluID0gdGhpcy50eC5hZGRJbnB1dCh0eEhhc2gsIHZvdXQsIG9wdGlvbnMuc2VxdWVuY2UsIG9wdGlvbnMuc2NyaXB0U2lnKVxuICB0aGlzLmlucHV0c1t2aW5dID0gaW5wdXRcbiAgdGhpcy5wcmV2VHhNYXBbcHJldlR4T3V0XSA9IHZpblxuICByZXR1cm4gdmluXG59XG5cblRyYW5zYWN0aW9uQnVpbGRlci5wcm90b3R5cGUuYWRkT3V0cHV0ID0gZnVuY3Rpb24gKHNjcmlwdFB1YktleSwgdmFsdWUpIHtcbiAgaWYgKCF0aGlzLl9fY2FuTW9kaWZ5T3V0cHV0cygpKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdObywgdGhpcyB3b3VsZCBpbnZhbGlkYXRlIHNpZ25hdHVyZXMnKVxuICB9XG5cbiAgLy8gQXR0ZW1wdCB0byBnZXQgYSBzY3JpcHQgaWYgaXQncyBhIGJhc2U1OCBhZGRyZXNzIHN0cmluZ1xuICBpZiAodHlwZW9mIHNjcmlwdFB1YktleSA9PT0gJ3N0cmluZycpIHtcbiAgICBzY3JpcHRQdWJLZXkgPSBiYWRkcmVzcy50b091dHB1dFNjcmlwdChzY3JpcHRQdWJLZXksIHRoaXMubmV0d29yaylcbiAgfVxuXG4gIHJldHVybiB0aGlzLnR4LmFkZE91dHB1dChzY3JpcHRQdWJLZXksIHZhbHVlKVxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLmJ1aWxkID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gdGhpcy5fX2J1aWxkKGZhbHNlKVxufVxuVHJhbnNhY3Rpb25CdWlsZGVyLnByb3RvdHlwZS5idWlsZEluY29tcGxldGUgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiB0aGlzLl9fYnVpbGQodHJ1ZSlcbn1cblxuVHJhbnNhY3Rpb25CdWlsZGVyLnByb3RvdHlwZS5fX2J1aWxkID0gZnVuY3Rpb24gKGFsbG93SW5jb21wbGV0ZSkge1xuICBpZiAoIWFsbG93SW5jb21wbGV0ZSkge1xuICAgIGlmICghdGhpcy50eC5pbnMubGVuZ3RoKSB0aHJvdyBuZXcgRXJyb3IoJ1RyYW5zYWN0aW9uIGhhcyBubyBpbnB1dHMnKVxuICAgIGlmICghdGhpcy50eC5vdXRzLmxlbmd0aCkgdGhyb3cgbmV3IEVycm9yKCdUcmFuc2FjdGlvbiBoYXMgbm8gb3V0cHV0cycpXG4gIH1cblxuICB2YXIgdHggPSB0aGlzLnR4LmNsb25lKClcbiAgLy8gQ3JlYXRlIHNjcmlwdCBzaWduYXR1cmVzIGZyb20gaW5wdXRzXG4gIHRoaXMuaW5wdXRzLmZvckVhY2goZnVuY3Rpb24gKGlucHV0LCBpKSB7XG4gICAgdmFyIHNjcmlwdFR5cGUgPSBpbnB1dC53aXRuZXNzU2NyaXB0VHlwZSB8fCBpbnB1dC5yZWRlZW1TY3JpcHRUeXBlIHx8IGlucHV0LnByZXZPdXRUeXBlXG4gICAgaWYgKCFzY3JpcHRUeXBlICYmICFhbGxvd0luY29tcGxldGUpIHRocm93IG5ldyBFcnJvcignVHJhbnNhY3Rpb24gaXMgbm90IGNvbXBsZXRlJylcbiAgICB2YXIgcmVzdWx0ID0gYnVpbGRJbnB1dChpbnB1dCwgYWxsb3dJbmNvbXBsZXRlKVxuXG4gICAgLy8gc2tpcCBpZiBubyByZXN1bHRcbiAgICBpZiAoIWFsbG93SW5jb21wbGV0ZSkge1xuICAgICAgaWYgKCFzdXBwb3J0ZWRUeXBlKHJlc3VsdC50eXBlKSAmJiByZXN1bHQudHlwZSAhPT0gYnRlbXBsYXRlcy50eXBlcy5QMldQS0gpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKHJlc3VsdC50eXBlICsgJyBub3Qgc3VwcG9ydGVkJylcbiAgICAgIH1cbiAgICB9XG5cbiAgICB0eC5zZXRJbnB1dFNjcmlwdChpLCByZXN1bHQuc2NyaXB0KVxuICAgIHR4LnNldFdpdG5lc3MoaSwgcmVzdWx0LndpdG5lc3MpXG4gIH0pXG5cbiAgaWYgKCFhbGxvd0luY29tcGxldGUpIHtcbiAgICAvLyBkbyBub3QgcmVseSBvbiB0aGlzLCBpdHMgbWVyZWx5IGEgbGFzdCByZXNvcnRcbiAgICBpZiAodGhpcy5fX292ZXJNYXhpbXVtRmVlcyh0eC52aXJ0dWFsU2l6ZSgpKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdUcmFuc2FjdGlvbiBoYXMgYWJzdXJkIGZlZXMnKVxuICAgIH1cbiAgfVxuXG4gIHJldHVybiB0eFxufVxuXG5mdW5jdGlvbiBjYW5TaWduIChpbnB1dCkge1xuICByZXR1cm4gaW5wdXQucHJldk91dFNjcmlwdCAhPT0gdW5kZWZpbmVkICYmXG4gICAgaW5wdXQuc2lnblNjcmlwdCAhPT0gdW5kZWZpbmVkICYmXG4gICAgaW5wdXQucHViS2V5cyAhPT0gdW5kZWZpbmVkICYmXG4gICAgaW5wdXQuc2lnbmF0dXJlcyAhPT0gdW5kZWZpbmVkICYmXG4gICAgaW5wdXQuc2lnbmF0dXJlcy5sZW5ndGggPT09IGlucHV0LnB1YktleXMubGVuZ3RoICYmXG4gICAgaW5wdXQucHViS2V5cy5sZW5ndGggPiAwICYmXG4gICAgKFxuICAgICAgaW5wdXQud2l0bmVzcyA9PT0gZmFsc2UgfHxcbiAgICAgIChpbnB1dC53aXRuZXNzID09PSB0cnVlICYmIGlucHV0LnZhbHVlICE9PSB1bmRlZmluZWQpXG4gICAgKVxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLnNpZ24gPSBmdW5jdGlvbiAodmluLCBrZXlQYWlyLCByZWRlZW1TY3JpcHQsIGhhc2hUeXBlLCB3aXRuZXNzVmFsdWUsIHdpdG5lc3NTY3JpcHQpIHtcbiAgZGVidWcoJ1NpZ25pbmcgdHJhbnNhY3Rpb246IChpbnB1dDogJWQsIGhhc2hUeXBlOiAlZCwgd2l0bmVzc1ZhbDogJXMsIHdpdG5lc3NTY3JpcHQ6ICVqKScsIHZpbiwgaGFzaFR5cGUsIHdpdG5lc3NWYWx1ZSwgd2l0bmVzc1NjcmlwdClcbiAgZGVidWcoJ1RyYW5zYWN0aW9uIEJ1aWxkZXIgbmV0d29yazogJWonLCB0aGlzLm5ldHdvcmspXG5cbiAgLy8gVE9ETzogcmVtb3ZlIGtleVBhaXIubmV0d29yayBtYXRjaGluZyBpbiA0LjAuMFxuICBpZiAoa2V5UGFpci5uZXR3b3JrICYmIGtleVBhaXIubmV0d29yayAhPT0gdGhpcy5uZXR3b3JrKSB0aHJvdyBuZXcgVHlwZUVycm9yKCdJbmNvbnNpc3RlbnQgbmV0d29yaycpXG4gIGlmICghdGhpcy5pbnB1dHNbdmluXSkgdGhyb3cgbmV3IEVycm9yKCdObyBpbnB1dCBhdCBpbmRleDogJyArIHZpbilcbiAgaGFzaFR5cGUgPSBoYXNoVHlwZSB8fCBUcmFuc2FjdGlvbi5TSUdIQVNIX0FMTFxuXG4gIHZhciBpbnB1dCA9IHRoaXMuaW5wdXRzW3Zpbl1cblxuICAvLyBpZiByZWRlZW1TY3JpcHQgd2FzIHByZXZpb3VzbHkgcHJvdmlkZWQsIGVuZm9yY2UgY29uc2lzdGVuY3lcbiAgaWYgKGlucHV0LnJlZGVlbVNjcmlwdCAhPT0gdW5kZWZpbmVkICYmXG4gICAgICByZWRlZW1TY3JpcHQgJiZcbiAgICAgICFpbnB1dC5yZWRlZW1TY3JpcHQuZXF1YWxzKHJlZGVlbVNjcmlwdCkpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ0luY29uc2lzdGVudCByZWRlZW1TY3JpcHQnKVxuICB9XG5cbiAgdmFyIGtwUHViS2V5ID0ga2V5UGFpci5wdWJsaWNLZXkgfHwga2V5UGFpci5nZXRQdWJsaWNLZXlCdWZmZXIoKVxuICBpZiAoIWNhblNpZ24oaW5wdXQpKSB7XG4gICAgaWYgKHdpdG5lc3NWYWx1ZSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICBpZiAoaW5wdXQudmFsdWUgIT09IHVuZGVmaW5lZCAmJiBpbnB1dC52YWx1ZSAhPT0gd2l0bmVzc1ZhbHVlKSB0aHJvdyBuZXcgRXJyb3IoJ0lucHV0IGRpZG5cXCd0IG1hdGNoIHdpdG5lc3NWYWx1ZScpXG4gICAgICB0eXBlZm9yY2UodHlwZXMuU2F0b3NoaSwgd2l0bmVzc1ZhbHVlKVxuICAgICAgaW5wdXQudmFsdWUgPSB3aXRuZXNzVmFsdWVcbiAgICB9XG5cbiAgICBkZWJ1ZygnUHJlcGFyaW5nIGlucHV0ICVkIGZvciBzaWduaW5nJywgdmluKVxuXG4gICAgaWYgKCFjYW5TaWduKGlucHV0KSkgcHJlcGFyZUlucHV0KGlucHV0LCBrcFB1YktleSwgcmVkZWVtU2NyaXB0LCB3aXRuZXNzVmFsdWUsIHdpdG5lc3NTY3JpcHQpXG4gICAgaWYgKCFjYW5TaWduKGlucHV0KSkgdGhyb3cgRXJyb3IoaW5wdXQucHJldk91dFR5cGUgKyAnIG5vdCBzdXBwb3J0ZWQnKVxuICB9XG5cbiAgLy8gcmVhZHkgdG8gc2lnblxuICB2YXIgc2lnbmF0dXJlSGFzaFxuICBpZiAoY29pbnMuaXNCaXRjb2luR29sZCh0aGlzLm5ldHdvcmspKSB7XG4gICAgc2lnbmF0dXJlSGFzaCA9IHRoaXMudHguaGFzaEZvckdvbGRTaWduYXR1cmUodmluLCBpbnB1dC5zaWduU2NyaXB0LCB3aXRuZXNzVmFsdWUsIGhhc2hUeXBlLCBpbnB1dC53aXRuZXNzKVxuICAgIGRlYnVnKCdDYWxjdWxhdGVkIEJURyBzaWdoYXNoICglcyknLCBzaWduYXR1cmVIYXNoLnRvU3RyaW5nKCdoZXgnKSlcbiAgfSBlbHNlIGlmIChjb2lucy5pc0JpdGNvaW5DYXNoKHRoaXMubmV0d29yaykgfHwgY29pbnMuaXNCaXRjb2luU1YodGhpcy5uZXR3b3JrKSkge1xuICAgIHNpZ25hdHVyZUhhc2ggPSB0aGlzLnR4Lmhhc2hGb3JDYXNoU2lnbmF0dXJlKHZpbiwgaW5wdXQuc2lnblNjcmlwdCwgd2l0bmVzc1ZhbHVlLCBoYXNoVHlwZSlcbiAgICBkZWJ1ZygnQ2FsY3VsYXRlZCBCQ0ggc2lnaGFzaCAoJXMpJywgc2lnbmF0dXJlSGFzaC50b1N0cmluZygnaGV4JykpXG4gIH0gZWxzZSBpZiAoY29pbnMuaXNaY2FzaCh0aGlzLm5ldHdvcmspKSB7XG4gICAgc2lnbmF0dXJlSGFzaCA9IHRoaXMudHguaGFzaEZvclpjYXNoU2lnbmF0dXJlKHZpbiwgaW5wdXQuc2lnblNjcmlwdCwgd2l0bmVzc1ZhbHVlLCBoYXNoVHlwZSlcbiAgICBkZWJ1ZygnQ2FsY3VsYXRlZCBaRUMgc2lnaGFzaCAoJXMpJywgc2lnbmF0dXJlSGFzaC50b1N0cmluZygnaGV4JykpXG4gIH0gZWxzZSB7XG4gICAgaWYgKGlucHV0LndpdG5lc3MpIHtcbiAgICAgIHNpZ25hdHVyZUhhc2ggPSB0aGlzLnR4Lmhhc2hGb3JXaXRuZXNzVjAodmluLCBpbnB1dC5zaWduU2NyaXB0LCB3aXRuZXNzVmFsdWUsIGhhc2hUeXBlKVxuICAgICAgZGVidWcoJ0NhbGN1bGF0ZWQgd2l0bmVzc3YwIHNpZ2hhc2ggKCVzKScsIHNpZ25hdHVyZUhhc2gudG9TdHJpbmcoJ2hleCcpKVxuICAgIH0gZWxzZSB7XG4gICAgICBzaWduYXR1cmVIYXNoID0gdGhpcy50eC5oYXNoRm9yU2lnbmF0dXJlKHZpbiwgaW5wdXQuc2lnblNjcmlwdCwgaGFzaFR5cGUpXG4gICAgICBkZWJ1ZygnQ2FsY3VsYXRlZCBzaWdoYXNoICglcyknLCBzaWduYXR1cmVIYXNoLnRvU3RyaW5nKCdoZXgnKSlcbiAgICB9XG4gIH1cblxuICAvLyBlbmZvcmNlIGluIG9yZGVyIHNpZ25pbmcgb2YgcHVibGljIGtleXNcbiAgdmFyIHNpZ25lZCA9IGlucHV0LnB1YktleXMuc29tZShmdW5jdGlvbiAocHViS2V5LCBpKSB7XG4gICAgaWYgKCFrcFB1YktleS5lcXVhbHMocHViS2V5KSkgcmV0dXJuIGZhbHNlXG4gICAgaWYgKGlucHV0LnNpZ25hdHVyZXNbaV0pIHRocm93IG5ldyBFcnJvcignU2lnbmF0dXJlIGFscmVhZHkgZXhpc3RzJylcbiAgICBpZiAoa3BQdWJLZXkubGVuZ3RoICE9PSAzMyAmJlxuICAgICAgaW5wdXQuc2lnblR5cGUgPT09IHNjcmlwdFR5cGVzLlAyV1BLSCkgdGhyb3cgbmV3IEVycm9yKCdCSVAxNDMgcmVqZWN0cyB1bmNvbXByZXNzZWQgcHVibGljIGtleXMgaW4gUDJXUEtIIG9yIFAyV1NIJylcblxuICAgIHZhciBzaWduYXR1cmUgPSBrZXlQYWlyLnNpZ24oc2lnbmF0dXJlSGFzaClcbiAgICBpZiAoQnVmZmVyLmlzQnVmZmVyKHNpZ25hdHVyZSkpIHNpZ25hdHVyZSA9IEVDU2lnbmF0dXJlLmZyb21SU0J1ZmZlcihzaWduYXR1cmUpXG5cbiAgICBkZWJ1ZygnUHJvZHVjZWQgc2lnbmF0dXJlIChyOiAlcywgczogJXMpJywgc2lnbmF0dXJlLnIsIHNpZ25hdHVyZS5zKVxuXG4gICAgaW5wdXQuc2lnbmF0dXJlc1tpXSA9IHNpZ25hdHVyZS50b1NjcmlwdFNpZ25hdHVyZShoYXNoVHlwZSlcbiAgICByZXR1cm4gdHJ1ZVxuICB9KVxuXG4gIGlmICghc2lnbmVkKSB0aHJvdyBuZXcgRXJyb3IoJ0tleSBwYWlyIGNhbm5vdCBzaWduIGZvciB0aGlzIGlucHV0Jylcbn1cblxuZnVuY3Rpb24gc2lnbmF0dXJlSGFzaFR5cGUgKGJ1ZmZlcikge1xuICByZXR1cm4gYnVmZmVyLnJlYWRVSW50OChidWZmZXIubGVuZ3RoIC0gMSlcbn1cblxuVHJhbnNhY3Rpb25CdWlsZGVyLnByb3RvdHlwZS5fX2Nhbk1vZGlmeUlucHV0cyA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIHRoaXMuaW5wdXRzLmV2ZXJ5KGZ1bmN0aW9uIChpbnB1dCkge1xuICAgIC8vIGFueSBzaWduYXR1cmVzP1xuICAgIGlmIChpbnB1dC5zaWduYXR1cmVzID09PSB1bmRlZmluZWQpIHJldHVybiB0cnVlXG5cbiAgICByZXR1cm4gaW5wdXQuc2lnbmF0dXJlcy5ldmVyeShmdW5jdGlvbiAoc2lnbmF0dXJlKSB7XG4gICAgICBpZiAoIXNpZ25hdHVyZSkgcmV0dXJuIHRydWVcbiAgICAgIHZhciBoYXNoVHlwZSA9IHNpZ25hdHVyZUhhc2hUeXBlKHNpZ25hdHVyZSlcblxuICAgICAgLy8gaWYgU0lHSEFTSF9BTllPTkVDQU5QQVkgaXMgc2V0LCBzaWduYXR1cmVzIHdvdWxkIG5vdFxuICAgICAgLy8gYmUgaW52YWxpZGF0ZWQgYnkgbW9yZSBpbnB1dHNcbiAgICAgIHJldHVybiBoYXNoVHlwZSAmIFRyYW5zYWN0aW9uLlNJR0hBU0hfQU5ZT05FQ0FOUEFZXG4gICAgfSlcbiAgfSlcbn1cblxuVHJhbnNhY3Rpb25CdWlsZGVyLnByb3RvdHlwZS5fX2Nhbk1vZGlmeU91dHB1dHMgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBuSW5wdXRzID0gdGhpcy50eC5pbnMubGVuZ3RoXG4gIHZhciBuT3V0cHV0cyA9IHRoaXMudHgub3V0cy5sZW5ndGhcblxuICByZXR1cm4gdGhpcy5pbnB1dHMuZXZlcnkoZnVuY3Rpb24gKGlucHV0KSB7XG4gICAgaWYgKGlucHV0LnNpZ25hdHVyZXMgPT09IHVuZGVmaW5lZCkgcmV0dXJuIHRydWVcblxuICAgIHJldHVybiBpbnB1dC5zaWduYXR1cmVzLmV2ZXJ5KGZ1bmN0aW9uIChzaWduYXR1cmUpIHtcbiAgICAgIGlmICghc2lnbmF0dXJlKSByZXR1cm4gdHJ1ZVxuICAgICAgdmFyIGhhc2hUeXBlID0gc2lnbmF0dXJlSGFzaFR5cGUoc2lnbmF0dXJlKVxuXG4gICAgICB2YXIgaGFzaFR5cGVNb2QgPSBoYXNoVHlwZSAmIDB4MWZcbiAgICAgIGlmIChoYXNoVHlwZU1vZCA9PT0gVHJhbnNhY3Rpb24uU0lHSEFTSF9OT05FKSByZXR1cm4gdHJ1ZVxuICAgICAgaWYgKGhhc2hUeXBlTW9kID09PSBUcmFuc2FjdGlvbi5TSUdIQVNIX1NJTkdMRSkge1xuICAgICAgICAvLyBpZiBTSUdIQVNIX1NJTkdMRSBpcyBzZXQsIGFuZCBuSW5wdXRzID4gbk91dHB1dHNcbiAgICAgICAgLy8gc29tZSBzaWduYXR1cmVzIHdvdWxkIGJlIGludmFsaWRhdGVkIGJ5IHRoZSBhZGRpdGlvblxuICAgICAgICAvLyBvZiBtb3JlIG91dHB1dHNcbiAgICAgICAgcmV0dXJuIG5JbnB1dHMgPD0gbk91dHB1dHNcbiAgICAgIH1cbiAgICB9KVxuICB9KVxufVxuXG5UcmFuc2FjdGlvbkJ1aWxkZXIucHJvdG90eXBlLl9fb3Zlck1heGltdW1GZWVzID0gZnVuY3Rpb24gKGJ5dGVzKSB7XG4gIC8vIG5vdCBhbGwgaW5wdXRzIHdpbGwgaGF2ZSAudmFsdWUgZGVmaW5lZFxuICB2YXIgaW5jb21pbmcgPSB0aGlzLmlucHV0cy5yZWR1Y2UoZnVuY3Rpb24gKGEsIHgpIHsgcmV0dXJuIGEgKyAoeC52YWx1ZSA+Pj4gMCkgfSwgMClcblxuICAvLyBidXQgYWxsIG91dHB1dHMgZG8sIGFuZCBpZiB3ZSBoYXZlIGFueSBpbnB1dCB2YWx1ZVxuICAvLyB3ZSBjYW4gaW1tZWRpYXRlbHkgZGV0ZXJtaW5lIGlmIHRoZSBvdXRwdXRzIGFyZSB0b28gc21hbGxcbiAgdmFyIG91dGdvaW5nID0gdGhpcy50eC5vdXRzLnJlZHVjZShmdW5jdGlvbiAoYSwgeCkgeyByZXR1cm4gYSArIHgudmFsdWUgfSwgMClcbiAgdmFyIGZlZSA9IGluY29taW5nIC0gb3V0Z29pbmdcbiAgdmFyIGZlZVJhdGUgPSBmZWUgLyBieXRlc1xuXG4gIHJldHVybiBmZWVSYXRlID4gdGhpcy5tYXhpbXVtRmVlUmF0ZVxufVxuXG5tb2R1bGUuZXhwb3J0cyA9IFRyYW5zYWN0aW9uQnVpbGRlclxuIl19