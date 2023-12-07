// Coins supported by bitgo-bitcoinjs-lib
var typeforce = require('typeforce');
var networks = require('./networks');
/**
 * @returns {Network[]} all known networks as array
 */
function getNetworkList() {
    return Object.keys(networks).map(function (n) { return networks[n]; });
}
/**
 * @param {Network} network
 * @returns {string} the name of the network. Returns undefined if network is not a value
 *                   of `networks`
 */
function getNetworkName(network) {
    return Object.keys(networks).find(function (n) { return networks[n] === network; });
}
/**
 * @param {Network} network
 * @returns {Object} the mainnet corresponding to a testnet
 */
function getMainnet(network) {
    switch (network) {
        case networks.bitcoin:
        case networks.testnet:
            return networks.bitcoin;
        case networks.bitcoincash:
        case networks.bitcoincashTestnet:
            return networks.bitcoincash;
        case networks.bitcoingold:
        case networks.bitcoingoldTestnet:
            return networks.bitcoingold;
        case networks.bitcoinsv:
        case networks.bitcoinsvTestnet:
            return networks.bitcoinsv;
        case networks.dash:
        case networks.dashTest:
            return networks.dash;
        case networks.litecoin:
        case networks.litecoinTest:
            return networks.litecoin;
        case networks.zcash:
        case networks.zcashTest:
            return networks.zcash;
    }
    throw new TypeError("invalid network");
}
/**
 * @param {Network} network
 * @returns {boolean} true iff network is a mainnet
 */
function isMainnet(network) {
    return getMainnet(network) === network;
}
/**
 * @param {Network} network
 * @returns {boolean} true iff network is a testnet
 */
function isTestnet(network) {
    return getMainnet(network) !== network;
}
/**
 *
 * @param {Network} network
 * @param {Network} otherNetwork
 * @returns {boolean} true iff both networks are for the same coin
 */
function isSameCoin(network, otherNetwork) {
    return getMainnet(network) === getMainnet(otherNetwork);
}
var mainnets = getNetworkList().filter(isMainnet);
var testnets = getNetworkList().filter(isTestnet);
/**
 * Map where keys are mainnet networks and values are testnet networks
 * @type {Map<Network, Network[]>}
 */
var mainnetTestnetPairs = new Map(mainnets.map(function (m) { return [m, testnets.filter(function (t) { return getMainnet(t) === m; })]; }));
/**
 * @param {Network} network
 * @returns {Network|undefined} - The testnet corresponding to a mainnet.
 *                               Returns undefined if a network has no testnet.
 */
function getTestnet(network) {
    if (isTestnet(network)) {
        return network;
    }
    var testnets = mainnetTestnetPairs.get(network);
    if (testnets === undefined) {
        throw new Error("invalid argument");
    }
    if (testnets.length === 0) {
        return;
    }
    if (testnets.length === 1) {
        return testnets[0];
    }
    throw new Error("more than one testnet for " + getNetworkName(network));
}
/**
 * @param {Network} network
 * @returns {boolean} true iff network bitcoin or testnet
 */
function isBitcoin(network) {
    return getMainnet(network) === networks.bitcoin;
}
/**
 * @param {Network} network
 * @returns {boolean} true iff network is bitcoincash or bitcoincashTestnet
 */
function isBitcoinCash(network) {
    return getMainnet(network) === networks.bitcoincash;
}
/**
 * @param {Network} network
 * @returns {boolean} true iff network is bitcoingold
 */
function isBitcoinGold(network) {
    return getMainnet(network) === networks.bitcoingold;
}
/**
 * @param {Network} network
 * @returns {boolean} true iff network is bitcoinsv or bitcoinsvTestnet
 */
function isBitcoinSV(network) {
    return getMainnet(network) === networks.bitcoinsv;
}
/**
 * @param {Network} network
 * @returns {boolean} true iff network is dash or dashTest
 */
function isDash(network) {
    return getMainnet(network) === networks.dash;
}
/**
 * @param {Network} network
 * @returns {boolean} true iff network is litecoin or litecoinTest
 */
function isLitecoin(network) {
    return getMainnet(network) === networks.litecoin;
}
/**
 * @param {Network} network
 * @returns {boolean} true iff network is zcash or zcashTest
 */
function isZcash(network) {
    return getMainnet(network) === networks.zcash;
}
/**
 * @param {Network} network
 * @returns {boolean} returns true iff network is any of the network stated in the argument
 */
var isValidNetwork = typeforce.oneOf(isBitcoin, isBitcoinCash, isBitcoinGold, isBitcoinSV, isDash, isLitecoin, isZcash);
module.exports = {
    BTC: networks.bitcoin.coin,
    BCH: networks.bitcoincash.coin,
    BSV: networks.bitcoinsv.coin,
    BTG: networks.bitcoingold.coin,
    DASH: networks.dash.coin,
    LTC: networks.litecoin.coin,
    ZEC: networks.zcash.coin,
    getNetworkList: getNetworkList,
    getNetworkName: getNetworkName,
    getMainnet: getMainnet,
    isMainnet: isMainnet,
    getTestnet: getTestnet,
    isTestnet: isTestnet,
    isSameCoin: isSameCoin,
    isBitcoin: isBitcoin,
    isBitcoinCash: isBitcoinCash,
    isBitcoinGold: isBitcoinGold,
    isBitcoinSV: isBitcoinSV,
    isDash: isDash,
    isLitecoin: isLitecoin,
    isZcash: isZcash,
    isValidNetwork: isValidNetwork,
    /**
     * @deprecated: use isValidNetwork
     */
    isValidCoin: isValidNetwork
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29pbnMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvY29pbnMuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEseUNBQXlDO0FBQ3pDLElBQU0sU0FBUyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQTtBQUV0QyxJQUFNLFFBQVEsR0FBRyxPQUFPLENBQUMsWUFBWSxDQUFDLENBQUE7QUFFdEM7O0dBRUc7QUFDSCxTQUFTLGNBQWM7SUFDckIsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxVQUFBLENBQUMsSUFBSSxPQUFBLFFBQVEsQ0FBQyxDQUFDLENBQUMsRUFBWCxDQUFXLENBQUMsQ0FBQTtBQUNwRCxDQUFDO0FBRUQ7Ozs7R0FJRztBQUNILFNBQVMsY0FBYyxDQUFFLE9BQU87SUFDOUIsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDLElBQUksQ0FBQyxVQUFBLENBQUMsSUFBSSxPQUFBLFFBQVEsQ0FBQyxDQUFDLENBQUMsS0FBSyxPQUFPLEVBQXZCLENBQXVCLENBQUMsQ0FBQTtBQUNqRSxDQUFDO0FBRUQ7OztHQUdHO0FBQ0gsU0FBUyxVQUFVLENBQUUsT0FBTztJQUMxQixRQUFRLE9BQU8sRUFBRTtRQUNmLEtBQUssUUFBUSxDQUFDLE9BQU8sQ0FBQztRQUN0QixLQUFLLFFBQVEsQ0FBQyxPQUFPO1lBQ25CLE9BQU8sUUFBUSxDQUFDLE9BQU8sQ0FBQTtRQUV6QixLQUFLLFFBQVEsQ0FBQyxXQUFXLENBQUM7UUFDMUIsS0FBSyxRQUFRLENBQUMsa0JBQWtCO1lBQzlCLE9BQU8sUUFBUSxDQUFDLFdBQVcsQ0FBQTtRQUU3QixLQUFLLFFBQVEsQ0FBQyxXQUFXLENBQUM7UUFDMUIsS0FBSyxRQUFRLENBQUMsa0JBQWtCO1lBQzlCLE9BQU8sUUFBUSxDQUFDLFdBQVcsQ0FBQTtRQUU3QixLQUFLLFFBQVEsQ0FBQyxTQUFTLENBQUM7UUFDeEIs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U0FBUyxXQUFBO0lBQ1QsVUFBVSxZQUFBO0lBQ1YsU0FBUyxXQUFBO0lBQ1QsVUFBVSxZQUFBO0lBRVYsU0FBUyxXQUFBO0lBQ1QsYUFBYSxlQUFBO0lBQ2IsYUFBYSxlQUFBO0lBQ2IsV0FBVyxhQUFBO0lBQ1gsTUFBTSxRQUFBO0lBQ04sVUFBVSxZQUFBO0lBQ1YsT0FBTyxTQUFBO0lBRVAsY0FBYyxnQkFBQTtJQUNkOztPQUVHO0lBQ0gsV0FBVyxFQUFFLGNBQWM7Q0FDNUIsQ0FBQSIsInNvdXJjZXNDb250ZW50IjpbIi8vIENvaW5zIHN1cHBvcnRlZCBieSBiaXRnby1iaXRjb2luanMtbGliXG5jb25zdCB0eXBlZm9yY2UgPSByZXF1aXJlKCd0eXBlZm9yY2UnKVxuXG5jb25zdCBuZXR3b3JrcyA9IHJlcXVpcmUoJy4vbmV0d29ya3MnKVxuXG4vKipcbiAqIEByZXR1cm5zIHtOZXR3b3JrW119IGFsbCBrbm93biBuZXR3b3JrcyBhcyBhcnJheVxuICovXG5mdW5jdGlvbiBnZXROZXR3b3JrTGlzdCAoKSB7XG4gIHJldHVybiBPYmplY3Qua2V5cyhuZXR3b3JrcykubWFwKG4gPT4gbmV0d29ya3Nbbl0pXG59XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7c3RyaW5nfSB0aGUgbmFtZSBvZiB0aGUgbmV0d29yay4gUmV0dXJucyB1bmRlZmluZWQgaWYgbmV0d29yayBpcyBub3QgYSB2YWx1ZVxuICogICAgICAgICAgICAgICAgICAgb2YgYG5ldHdvcmtzYFxuICovXG5mdW5jdGlvbiBnZXROZXR3b3JrTmFtZSAobmV0d29yaykge1xuICByZXR1cm4gT2JqZWN0LmtleXMobmV0d29ya3MpLmZpbmQobiA9PiBuZXR3b3Jrc1tuXSA9PT0gbmV0d29yaylcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtPYmplY3R9IHRoZSBtYWlubmV0IGNvcnJlc3BvbmRpbmcgdG8gYSB0ZXN0bmV0XG4gKi9cbmZ1bmN0aW9uIGdldE1haW5uZXQgKG5ldHdvcmspIHtcbiAgc3dpdGNoIChuZXR3b3JrKSB7XG4gICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luOlxuICAgIGNhc2UgbmV0d29ya3MudGVzdG5ldDpcbiAgICAgIHJldHVybiBuZXR3b3Jrcy5iaXRjb2luXG5cbiAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5jYXNoOlxuICAgIGNhc2UgbmV0d29ya3MuYml0Y29pbmNhc2hUZXN0bmV0OlxuICAgICAgcmV0dXJuIG5ldHdvcmtzLmJpdGNvaW5jYXNoXG5cbiAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5nb2xkOlxuICAgIGNhc2UgbmV0d29ya3MuYml0Y29pbmdvbGRUZXN0bmV0OlxuICAgICAgcmV0dXJuIG5ldHdvcmtzLmJpdGNvaW5nb2xkXG5cbiAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5zdjpcbiAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5zdlRlc3RuZXQ6XG4gICAgICByZXR1cm4gbmV0d29ya3MuYml0Y29pbnN2XG5cbiAgICBjYXNlIG5ldHdvcmtzLmRhc2g6XG4gICAgY2FzZSBuZXR3b3Jrcy5kYXNoVGVzdDpcbiAgICAgIHJldHVybiBuZXR3b3Jrcy5kYXNoXG5cbiAgICBjYXNlIG5ldHdvcmtzLmxpdGVjb2luOlxuICAgIGNhc2UgbmV0d29ya3MubGl0ZWNvaW5UZXN0OlxuICAgICAgcmV0dXJuIG5ldHdvcmtzLmxpdGVjb2luXG5cbiAgICBjYXNlIG5ldHdvcmtzLnpjYXNoOlxuICAgIGNhc2UgbmV0d29ya3MuemNhc2hUZXN0OlxuICAgICAgcmV0dXJuIG5ldHdvcmtzLnpjYXNoXG4gIH1cbiAgdGhyb3cgbmV3IFR5cGVFcnJvcihgaW52YWxpZCBuZXR3b3JrYClcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmZiBuZXR3b3JrIGlzIGEgbWFpbm5ldFxuICovXG5mdW5jdGlvbiBpc01haW5uZXQgKG5ldHdvcmspIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcmtcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmZiBuZXR3b3JrIGlzIGEgdGVzdG5ldFxuICovXG5mdW5jdGlvbiBpc1Rlc3RuZXQgKG5ldHdvcmspIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgIT09IG5ldHdvcmtcbn1cblxuLyoqXG4gKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcGFyYW0ge05ldHdvcmt9IG90aGVyTmV0d29ya1xuICogQHJldHVybnMge2Jvb2xlYW59IHRydWUgaWZmIGJvdGggbmV0d29ya3MgYXJlIGZvciB0aGUgc2FtZSBjb2luXG4gKi9cbmZ1bmN0aW9uIGlzU2FtZUNvaW4gKG5ldHdvcmssIG90aGVyTmV0d29yaykge1xuICByZXR1cm4gZ2V0TWFpbm5ldChuZXR3b3JrKSA9PT0gZ2V0TWFpbm5ldChvdGhlck5ldHdvcmspXG59XG5cbmNvbnN0IG1haW5uZXRzID0gZ2V0TmV0d29ya0xpc3QoKS5maWx0ZXIoaXNNYWlubmV0KVxuY29uc3QgdGVzdG5ldHMgPSBnZXROZXR3b3JrTGlzdCgpLmZpbHRlcihpc1Rlc3RuZXQpXG5cbi8qKlxuICogTWFwIHdoZXJlIGtleXMgYXJlIG1haW5uZXQgbmV0d29ya3MgYW5kIHZhbHVlcyBhcmUgdGVzdG5ldCBuZXR3b3Jrc1xuICogQHR5cGUge01hcDxOZXR3b3JrLCBOZXR3b3JrW10+fVxuICovXG5jb25zdCBtYWlubmV0VGVzdG5ldFBhaXJzID0gbmV3IE1hcChcbiAgbWFpbm5ldHMubWFwKG0gPT4gW20sIHRlc3RuZXRzLmZpbHRlcih0ID0+IGdldE1haW5uZXQodCkgPT09IG0pXSlcbilcblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtOZXR3b3JrfHVuZGVmaW5lZH0gLSBUaGUgdGVzdG5ldCBjb3JyZXNwb25kaW5nIHRvIGEgbWFpbm5ldC5cbiAqICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJldHVybnMgdW5kZWZpbmVkIGlmIGEgbmV0d29yayBoYXMgbm8gdGVzdG5ldC5cbiAqL1xuZnVuY3Rpb24gZ2V0VGVzdG5ldCAobmV0d29yaykge1xuICBpZiAoaXNUZXN0bmV0KG5ldHdvcmspKSB7XG4gICAgcmV0dXJuIG5ldHdvcmtcbiAgfVxuICBjb25zdCB0ZXN0bmV0cyA9IG1haW5uZXRUZXN0bmV0UGFpcnMuZ2V0KG5ldHdvcmspXG4gIGlmICh0ZXN0bmV0cyA9PT0gdW5kZWZpbmVkKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIGFyZ3VtZW50YClcbiAgfVxuICBpZiAodGVzdG5ldHMubGVuZ3RoID09PSAwKSB7XG4gICAgcmV0dXJuXG4gIH1cbiAgaWYgKHRlc3RuZXRzLmxlbmd0aCA9PT0gMSkge1xuICAgIHJldHVybiB0ZXN0bmV0c1swXVxuICB9XG4gIHRocm93IG5ldyBFcnJvcihgbW9yZSB0aGFuIG9uZSB0ZXN0bmV0IGZvciAke2dldE5ldHdvcmtOYW1lKG5ldHdvcmspfWApXG59XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7Ym9vbGVhbn0gdHJ1ZSBpZmYgbmV0d29yayBiaXRjb2luIG9yIHRlc3RuZXRcbiAqL1xuZnVuY3Rpb24gaXNCaXRjb2luIChuZXR3b3JrKSB7XG4gIHJldHVybiBnZXRNYWlubmV0KG5ldHdvcmspID09PSBuZXR3b3Jrcy5iaXRjb2luXG59XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7Ym9vbGVhbn0gdHJ1ZSBpZmYgbmV0d29yayBpcyBiaXRjb2luY2FzaCBvciBiaXRjb2luY2FzaFRlc3RuZXRcbiAqL1xuZnVuY3Rpb24gaXNCaXRjb2luQ2FzaCAobmV0d29yaykge1xuICByZXR1cm4gZ2V0TWFpbm5ldChuZXR3b3JrKSA9PT0gbmV0d29ya3MuYml0Y29pbmNhc2hcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtib29sZWFufSB0cnVlIGlmZiBuZXR3b3JrIGlzIGJpdGNvaW5nb2xkXG4gKi9cbmZ1bmN0aW9uIGlzQml0Y29pbkdvbGQgKG5ldHdvcmspIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcmtzLmJpdGNvaW5nb2xkXG59XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7Ym9vbGVhbn0gdHJ1ZSBpZmYgbmV0d29yayBpcyBiaXRjb2luc3Ygb3IgYml0Y29pbnN2VGVzdG5ldFxuICovXG5mdW5jdGlvbiBpc0JpdGNvaW5TViAobmV0d29yaykge1xuICByZXR1cm4gZ2V0TWFpbm5ldChuZXR3b3JrKSA9PT0gbmV0d29ya3MuYml0Y29pbnN2XG59XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7Ym9vbGVhbn0gdHJ1ZSBpZmYgbmV0d29yayBpcyBkYXNoIG9yIGRhc2hUZXN0XG4gKi9cbmZ1bmN0aW9uIGlzRGFzaCAobmV0d29yaykge1xuICByZXR1cm4gZ2V0TWFpbm5ldChuZXR3b3JrKSA9PT0gbmV0d29ya3MuZGFzaFxufVxuXG4vKipcbiAqIEBwYXJhbSB7TmV0d29ya30gbmV0d29ya1xuICogQHJldHVybnMge2Jvb2xlYW59IHRydWUgaWZmIG5ldHdvcmsgaXMgbGl0ZWNvaW4gb3IgbGl0ZWNvaW5UZXN0XG4gKi9cbmZ1bmN0aW9uIGlzTGl0ZWNvaW4gKG5ldHdvcmspIHtcbiAgcmV0dXJuIGdldE1haW5uZXQobmV0d29yaykgPT09IG5ldHdvcmtzLmxpdGVjb2luXG59XG5cbi8qKlxuICogQHBhcmFtIHtOZXR3b3JrfSBuZXR3b3JrXG4gKiBAcmV0dXJucyB7Ym9vbGVhbn0gdHJ1ZSBpZmYgbmV0d29yayBpcyB6Y2FzaCBvciB6Y2FzaFRlc3RcbiAqL1xuZnVuY3Rpb24gaXNaY2FzaCAobmV0d29yaykge1xuICByZXR1cm4gZ2V0TWFpbm5ldChuZXR3b3JrKSA9PT0gbmV0d29ya3MuemNhc2hcbn1cblxuLyoqXG4gKiBAcGFyYW0ge05ldHdvcmt9IG5ldHdvcmtcbiAqIEByZXR1cm5zIHtib29sZWFufSByZXR1cm5zIHRydWUgaWZmIG5ldHdvcmsgaXMgYW55IG9mIHRoZSBuZXR3b3JrIHN0YXRlZCBpbiB0aGUgYXJndW1lbnRcbiAqL1xuY29uc3QgaXNWYWxpZE5ldHdvcmsgPSB0eXBlZm9yY2Uub25lT2YoXG4gIGlzQml0Y29pbixcbiAgaXNCaXRjb2luQ2FzaCxcbiAgaXNCaXRjb2luR29sZCxcbiAgaXNCaXRjb2luU1YsXG4gIGlzRGFzaCxcbiAgaXNMaXRlY29pbixcbiAgaXNaY2FzaFxuKVxuXG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgQlRDOiBuZXR3b3Jrcy5iaXRjb2luLmNvaW4sXG4gIEJDSDogbmV0d29ya3MuYml0Y29pbmNhc2guY29pbixcbiAgQlNWOiBuZXR3b3Jrcy5iaXRjb2luc3YuY29pbixcbiAgQlRHOiBuZXR3b3Jrcy5iaXRjb2luZ29sZC5jb2luLFxuICBEQVNIOiBuZXR3b3Jrcy5kYXNoLmNvaW4sXG4gIExUQzogbmV0d29ya3MubGl0ZWNvaW4uY29pbixcbiAgWkVDOiBuZXR3b3Jrcy56Y2FzaC5jb2luLFxuXG4gIGdldE5ldHdvcmtMaXN0LFxuICBnZXROZXR3b3JrTmFtZSxcblxuICBnZXRNYWlubmV0LFxuICBpc01haW5uZXQsXG4gIGdldFRlc3RuZXQsXG4gIGlzVGVzdG5ldCxcbiAgaXNTYW1lQ29pbixcblxuICBpc0JpdGNvaW4sXG4gIGlzQml0Y29pbkNhc2gsXG4gIGlzQml0Y29pbkdvbGQsXG4gIGlzQml0Y29pblNWLFxuICBpc0Rhc2gsXG4gIGlzTGl0ZWNvaW4sXG4gIGlzWmNhc2gsXG5cbiAgaXNWYWxpZE5ldHdvcmssXG4gIC8qKlxuICAgKiBAZGVwcmVjYXRlZDogdXNlIGlzVmFsaWROZXR3b3JrXG4gICAqL1xuICBpc1ZhbGlkQ29pbjogaXNWYWxpZE5ldHdvcmtcbn1cbiJdfQ==