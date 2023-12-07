/*

The values for the various fork coins can be found in these files:

property       filename                  varname                           notes
------------------------------------------------------------------------------------------------------------------------
messagePrefix  src/validation.cpp        strMessageMagic                   Format `${CoinName} Signed Message`
bech32_hrp     src/chainparams.cpp       bech32_hrp                        Only for some networks
bip32.public   src/chainparams.cpp       base58Prefixes[EXT_PUBLIC_KEY]    Mainnets have same value, testnets have same value
bip32.private  src/chainparams.cpp       base58Prefixes[EXT_SECRET_KEY]    Mainnets have same value, testnets have same value
pubKeyHash     src/chainparams.cpp       base58Prefixes[PUBKEY_ADDRESS]
scriptHash     src/chainparams.cpp       base58Prefixes[SCRIPT_ADDRESS]
wif            src/chainparams.cpp       base58Prefixes[SECRET_KEY]        Testnets have same value
forkId         src/script/interpreter.h  FORKID_*

*/
var coins = {
    BCH: 'bch',
    BSV: 'bsv',
    BTC: 'btc',
    BTG: 'btg',
    LTC: 'ltc',
    ZEC: 'zec',
    DASH: 'dash'
};
function getDefaultBip32Mainnet() {
    return {
        // base58 'xpub'
        public: 0x0488b21e,
        // base58 'xprv'
        private: 0x0488ade4
    };
}
function getDefaultBip32Testnet() {
    return {
        // base58 'tpub'
        public: 0x043587cf,
        // base58 'tprv'
        private: 0x04358394
    };
}
module.exports = {
    // https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp
    // https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp
    bitcoin: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bech32: 'bc',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x00,
        scriptHash: 0x05,
        wif: 0x80,
        coin: coins.BTC
    },
    testnet: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bech32: 'tb',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
        coin: coins.BTC
    },
    // https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/validation.cpp
    // https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/chainparams.cpp
    bitcoincash: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x00,
        scriptHash: 0x05,
        wif: 0x80,
        coin: coins.BCH,
        forkId: 0x00
    },
    bitcoincashTestnet: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
        coin: coins.BCH
    },
    // https://github.com/BTCGPU/BTCGPU/blob/master/src/validation.cpp
    // https://github.com/BTCGPU/BTCGPU/blob/master/src/chainparams.cpp
    // https://github.com/BTCGPU/BTCGPU/blob/master/src/script/interpreter.h
    bitcoingold: {
        messagePrefix: '\x18Bitcoin Gold Signed Message:\n',
        bech32: 'btg',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x26,
        scriptHash: 0x17,
        wif: 0x80,
        forkId: 79,
        coin: coins.BTG
    },
    bitcoingoldTestnet: {
        messagePrefix: '\x18Bitcoin Gold Signed Message:\n',
        bech32: 'tbtg',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 111,
        scriptHash: 196,
        wif: 0xef,
        forkId: 79,
        coin: coins.BTG
    },
    // https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/validation.cpp
    // https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/chainparams.cpp
    bitcoinsv: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x00,
        scriptHash: 0x05,
        wif: 0x80,
        coin: coins.BSV,
        forkId: 0x00
    },
    bitcoinsvTestnet: {
        messagePrefix: '\x18Bitcoin Signed Message:\n',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
        coin: coins.BSV
    },
    // https://github.com/dashpay/dash/blob/master/src/validation.cpp
    // https://github.com/dashpay/dash/blob/master/src/chainparams.cpp
    dash: {
        messagePrefix: '\x19DarkCoin Signed Message:\n',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x4c,
        scriptHash: 0x10,
        wif: 0xcc,
        coin: coins.DASH
    },
    dashTest: {
        messagePrefix: '\x19DarkCoin Signed Message:\n',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 0x8c,
        scriptHash: 0x13,
        wif: 0xef,
        coin: coins.DASH
    },
    // https://github.com/litecoin-project/litecoin/blob/master/src/validation.cpp
    // https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp
    litecoin: {
        messagePrefix: '\x19Litecoin Signed Message:\n',
        bech32: 'ltc',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x30,
        scriptHash: 0x32,
        wif: 0xb0,
        coin: coins.LTC
    },
    litecoinTest: {
        messagePrefix: '\x19Litecoin Signed Message:\n',
        bech32: 'tltc',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 0x6f,
        scriptHash: 0x3a,
        wif: 0xef,
        coin: coins.LTC
    },
    // https://github.com/zcash/zcash/blob/master/src/validation.cpp
    // https://github.com/zcash/zcash/blob/master/src/chainparams.cpp
    zcash: {
        messagePrefix: '\x18ZCash Signed Message:\n',
        bip32: getDefaultBip32Mainnet(),
        pubKeyHash: 0x1cb8,
        scriptHash: 0x1cbd,
        wif: 0x80,
        // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
        // dummy value.
        consensusBranchId: {
            1: 0x00,
            2: 0x00,
            3: 0x5ba81b19,
            // 4: 0x76b809bb (old Sapling branch id). Blossom branch id becomes effective after block 653600
            // 4: 0x2bb40e60
            // 4: 0xf5b9230b (Heartwood branch id, see https://zips.z.cash/zip-0250)
            4: 0xe9ff75a6 // (Canopy branch id, see https://zips.z.cash/zip-0251)
        },
        coin: coins.ZEC
    },
    zcashTest: {
        messagePrefix: '\x18ZCash Signed Message:\n',
        bip32: getDefaultBip32Testnet(),
        pubKeyHash: 0x1d25,
        scriptHash: 0x1cba,
        wif: 0xef,
        consensusBranchId: {
            1: 0x00,
            2: 0x00,
            3: 0x5ba81b19,
            // 4: 0x76b809bb (old Sapling branch id)
            // 4: 0x2bb40e60
            // 4: 0xf5b9230b (Heartwood branch id, see https://zips.z.cash/zip-0250)
            4: 0xe9ff75a6 // (Canopy branch id, see https://zips.z.cash/zip-0251)
        },
        coin: coins.ZEC
    }
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibmV0d29ya3MuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvbmV0d29ya3MuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7Ozs7Ozs7Ozs7Ozs7OztFQWVFO0FBRUYsSUFBTSxLQUFLLEdBQUc7SUFDWixHQUFHLEVBQUUsS0FBSztJQUNWLEdBQUcsRUFBRSxLQUFLO0lBQ1YsR0FBRyxFQUFFLEtBQUs7SUFDVixHQUFHLEVBQUUsS0FBSztJQUNWLEdBQUcsRUFBRSxLQUFLO0lBQ1YsR0FBRyxFQUFFLEtBQUs7SUFDVixJQUFJLEVBQUUsTUFBTTtDQUNiLENBQUE7QUFFRCxTQUFTLHNCQUFzQjtJQUM3QixPQUFPO1FBQ0wsZ0JBQWdCO1FBQ2hCLE1BQU0sRUFBRSxVQUFVO1FBQ2xCLGdCQUFnQjtRQUNoQixPQUFPLEVBQUUsVUFBVTtLQUNwQixDQUFBO0FBQ0gsQ0FBQztBQUVELFNBQVMsc0JBQXNCO0lBQzdCLE9BQU87UUFDTCxnQkFBZ0I7UUFDaEIsTUFBTSxFQUFFLFVBQVU7UUFDbEIsZ0JBQWdCO1FBQ2hCLE9BQU8sRUFBRSxVQUFVO0tBQ3BCLENBQUE7QUFDSCxDQUFDO0FBRUQsTUFBTSxDQUFDLE9BQU8sR0FBRztJQUVmLG9FQUFvRTtJQUNwRSxxRUFBcUU7SUFDckUsT0FBTyxFQUFFO1FBQ1AsYUFBYSxFQUFFLCtCQUErQjtRQUM5QyxNQUFNLEVBQUUsSUFBSTtRQUNaLEtBQUssRUFBRSxzQkFBc0IsRUFBRTtRQUMvQixVQUFVLEVBQUUsSUFBSTtRQUNoQixVQUFVLEVBQUUsSUFBSTtRQUNoQixHQUFHLEVBQUUsSUFBSTtRQUNULElBQUksRUFBRSxLQUFLLENBQUMsR0FBRztLQUNoQjtJQUNELE9BQU8sRUFBRTtRQUNQLGFBQWEsRUFBRSwrQkFBK0I7UUFDOUMsTUFBTSxFQUFFLElBQUk7UUFDWixLQUFLLEVBQUUsc0JBQXNCLEVBQUU7UUFDL0IsVUFBVSxFQUFFLElBQUk7UUFDaEIsVUFBVSxFQUFFLElBQUk7UUFDaEIsR0FBRyxFQUFFLElBQUk7UUFDVCxJQUFJLEVBQUUsS0FBSyxDQUFDLEdBQUc7S0FDaEI7SUFFRCw0RUFBNEU7SUFDNUUsNkVBQTZFO0lBQzdFLFdBQVcsRUFBRTtRQUNYLGFBQWEsRUFBRSwrQkFBK0I7UUFDOUMsS0FBSyxFQUFFLHNCQUFzQixFQUFFO1FBQy9CLFVBQVUsRUFBRSxJQUFJO1FBQ2hCLFVBQVUsRUFBRSxJQUFJO1FBQ2hCLEdBQUcsRUFBRSxJQUFJO1FBQ1QsSUFBSSxFQUFFLEtBQUssQ0FBQyxHQUFHO1FBQ2YsTUFBTSxFQUFFLElBQUk7S0FDYjtJQUNELGtCQUFrQixFQUFFO1FBQ2xCLGFBQWEsRUFBRSwrQkFBK0I7UUFDOUMsS0FBSyxFQUFFLHNCQUFzQixFQUFFO1FBQy9CLFVBQVUsRUFBRSxJQUFJO1FBQ2hCLFVBQVUsRUFBRSxJQUFJO1FBQ2hCLEdBQUcsRUFBRSxJQUFJO1FBQ1QsSUFBSSxFQUFFLEtBQUssQ0FBQyxHQUFHO0tBQ2hCO0lBRUQsa0VBQWtFO0lBQ2xFLG1FQUFtRTtJQUNuRSx3RUFBd0U7SUFDeEUsV0FBVyxFQUFFO1FBQ1gsYUFBYSxFQUFFLG9DQUFvQztRQUNuRCxNQUFNLEVBQUUsS0FBSztRQUNiLEtBQUssRUFBRSxzQkFBc0IsRUFBRTtRQUMvQixVQUFVLEVBQUUsSUFBSTtRQUNoQixVQUFVLEVBQUUsSUFBSTtRQUNoQixHQUFHLEVBQUUsSUFBSTtRQUNULE1BQU0sRUFBRSxFQUFFO1FBQ1YsSUFBSSxFQUFFLEtBQUssQ0FBQyxHQUFHO0tBQ2hCO0lBQ0Qsa0JBQWtCLEVBQUU7UUFDbEIsYUFBYSxFQUFFLG9DQUFvQztRQUNuRCxNQUFNLEVBQUUsTUFBTTtRQUNkLEtBQUssRUFBRSxzQkFBc0IsRUFBRTtRQUMvQixVQUFVLEVBQUUsR0FBRztRQUNmLFVBQVUsRUFBRSxHQUFHO1FBQ2YsR0FBRyxFQUFFLElBQUk7UUFDVCxNQUFNLEVBQUUsRUFBRTtRQUNWLElBQUksRUFBRSxLQUFLLENBQUMsR0FBRztLQUNoQjtJQUVELDBFQUEwRTtJQUMxRSwyRUFBMkU7SUFDM0UsU0FBUyxFQUFFO1FBQ1QsYUFBYSxFQUFFLCtCQUErQjtRQUM5QyxLQUFLLEVBQUUsc0JBQXNCLEVBQUU7UUFDL0IsVUFBVSxFQUFFLElBQUk7UUFDaEIsVUFBVSxFQUFFLElBQUk7UUFDaEIsR0FBRyxFQUFFLElBQUk7UUFDVCxJQUFJLEVBQUUsS0FBSyxDQUFDLEdBQUc7UUFDZixNQUFNLEVBQUUsSUFBSTtLQUNiO0lBQ0QsZ0JBQWdCLEVBQUU7UUFDaEIsYUFBYSxFQUFFLCtCQUErQjtRQUM5QyxLQUFLLEVBQUUsc0JBQXNCLEVBQUU7UUFDL0IsVUFBVSxFQUFFLElBQUk7UUFDaEIsVUFBVSxFQUFFLElBQUk7UUFDaEIsR0FBRyxFQUFFLElBQUk7UUFDVCxJQUFJLEVBQUUsS0FBSyxDQUFDLEdBQUc7S0FDaEI7SUFFRCxpRUFBaUU7SUFDakUsa0VBQWtFO0lBQ2xFLElBQUksRUFBRTtRQUNKLGFBQWEsRUFBRSxnQ0FBZ0M7UUFDL0MsS0FBSyxFQUFFLHNCQUFzQixFQUFFO1FBQy9CLFVBQVUsRUFBRSxJQUFJO1FBQ2hCLFVBQVUsRUFBRSxJQUFJO1FBQ2hCLEdBQUcsRUFBRSxJQUFJO1FBQ1QsSUFBSSxFQUFFLEtBQUssQ0FBQyxJQUFJO0tBQ2pCO0lBQ0QsUUFBUSxFQUFFO1FBQ1IsYUFBYSxFQUFFLGdDQUFnQztRQUMvQyxLQUFLLEVBQUUsc0JBQXNCLEVBQUU7UUFDL0IsVUFBVSxFQUFFLElBQUk7UUFDaEIsVUFBVSxFQUFFLElBQUk7UUFDaEIsR0FBRyxFQUFFLElBQUk7UUFDVCxJQUFJLEVBQUUsS0FBSyxDQUFDLElBQUk7S0FDakI7SUFFRCw4RUFBOEU7SUFDOUUsK0VBQStFO0lBQy9FLFFBQVEsRUFBRTtRQUNSLGFBQWEsRUFBRSxnQ0FBZ0M7UUFDL0MsTUFBTSxFQUFFLEtBQUs7UUFDYixLQUFLLEVBQUUsc0JBQXNCLEVBQUU7UUFDL0IsVUFBVSxFQUFFLElBQUk7UUFDaEIsVUFBVSxFQUFFLElBQUk7UUFDaEIsR0FBRyxFQUFFLElBQUk7UUFDVCxJQUFJLEVBQUUsS0FBSyxDQUFDLEdBQUc7S0FDaEI7SUFDRCxZQUFZLEVBQUU7UUFDWixhQUFhLEVBQUUsZ0NBQWdDO1FBQy9DLE1BQU0sRUFBRSxNQUFNO1FBQ2QsS0FBSyxFQUFFLHNCQUFzQixFQUFFO1FBQy9CLFVBQVUsRUFBRSxJQUFJO1FBQ2hCLFVBQVUsRUFBRSxJQUFJO1FBQ2hCLEdBQUcsRUFBRSxJQUFJO1FBQ1QsSUFBSSxFQUFFLEtBQUssQ0FBQyxHQUFHO0tBQ2hCO0lBRUQsZ0VBQWdFO0lBQ2hFLGlFQUFpRTtJQUNqRSxLQUFLLEVBQUU7UUFDTCxhQUFhLEVBQUUsNkJBQTZCO1FBQzVDLEtBQUssRUFBRSxzQkFBc0IsRUFBRTtRQUMvQixVQUFVLEVBQUUsTUFBTTtRQUNsQixVQUFVLEVBQUUsTUFBTTtRQUNsQixHQUFHLEVBQUUsSUFBSTtRQUNULDRHQUE0RztRQUM1RyxlQUFlO1FBQ2YsaUJBQWlCLEVBQUU7WUFDakIsQ0FBQyxFQUFFLElBQUk7WUFDUCxDQUFDLEVBQUUsSUFBSTtZQUNQLENBQUMsRUFBRSxVQUFVO1lBQ2IsZ0dBQWdHO1lBQ2hHLGdCQUFnQjtZQUNoQix3RUFBd0U7WUFDeEUsQ0FBQyxFQUFFLFVBQVUsQ0FBQyx1REFBdUQ7U0FDdEU7UUFDRCxJQUFJLEVBQUUsS0FBSyxDQUFDLEdBQUc7S0FDaEI7SUFDRCxTQUFTLEVBQUU7UUFDVCxhQUFhLEVBQUUsNkJBQTZCO1FBQzVDLEtBQUssRUFBRSxzQkFBc0IsRUFBRTtRQUMvQixVQUFVLEVBQUUsTUFBTTtRQUNsQixVQUFVLEVBQUUsTUFBTTtRQUNsQixHQUFHLEVBQUUsSUFBSTtRQUNULGlCQUFpQixFQUFFO1lBQ2pCLENBQUMsRUFBRSxJQUFJO1lBQ1AsQ0FBQyxFQUFFLElBQUk7WUFDUCxDQUFDLEVBQUUsVUFBVTtZQUNiLHdDQUF3QztZQUN4QyxnQkFBZ0I7WUFDaEIsd0VBQXdFO1lBQ3hFLENBQUMsRUFBRSxVQUFVLENBQUMsdURBQXVEO1NBQ3RFO1FBQ0QsSUFBSSxFQUFFLEtBQUssQ0FBQyxHQUFHO0tBQ2hCO0NBQ0YsQ0FBQSIsInNvdXJjZXNDb250ZW50IjpbIi8qXG5cblRoZSB2YWx1ZXMgZm9yIHRoZSB2YXJpb3VzIGZvcmsgY29pbnMgY2FuIGJlIGZvdW5kIGluIHRoZXNlIGZpbGVzOlxuXG5wcm9wZXJ0eSAgICAgICBmaWxlbmFtZSAgICAgICAgICAgICAgICAgIHZhcm5hbWUgICAgICAgICAgICAgICAgICAgICAgICAgICBub3Rlc1xuLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5tZXNzYWdlUHJlZml4ICBzcmMvdmFsaWRhdGlvbi5jcHAgICAgICAgIHN0ck1lc3NhZ2VNYWdpYyAgICAgICAgICAgICAgICAgICBGb3JtYXQgYCR7Q29pbk5hbWV9IFNpZ25lZCBNZXNzYWdlYFxuYmVjaDMyX2hycCAgICAgc3JjL2NoYWlucGFyYW1zLmNwcCAgICAgICBiZWNoMzJfaHJwICAgICAgICAgICAgICAgICAgICAgICAgT25seSBmb3Igc29tZSBuZXR3b3Jrc1xuYmlwMzIucHVibGljICAgc3JjL2NoYWlucGFyYW1zLmNwcCAgICAgICBiYXNlNThQcmVmaXhlc1tFWFRfUFVCTElDX0tFWV0gICAgTWFpbm5ldHMgaGF2ZSBzYW1lIHZhbHVlLCB0ZXN0bmV0cyBoYXZlIHNhbWUgdmFsdWVcbmJpcDMyLnByaXZhdGUgIHNyYy9jaGFpbnBhcmFtcy5jcHAgICAgICAgYmFzZTU4UHJlZml4ZXNbRVhUX1NFQ1JFVF9LRVldICAgIE1haW5uZXRzIGhhdmUgc2FtZSB2YWx1ZSwgdGVzdG5ldHMgaGF2ZSBzYW1lIHZhbHVlXG5wdWJLZXlIYXNoICAgICBzcmMvY2hhaW5wYXJhbXMuY3BwICAgICAgIGJhc2U1OFByZWZpeGVzW1BVQktFWV9BRERSRVNTXVxuc2NyaXB0SGFzaCAgICAgc3JjL2NoYWlucGFyYW1zLmNwcCAgICAgICBiYXNlNThQcmVmaXhlc1tTQ1JJUFRfQUREUkVTU11cbndpZiAgICAgICAgICAgIHNyYy9jaGFpbnBhcmFtcy5jcHAgICAgICAgYmFzZTU4UHJlZml4ZXNbU0VDUkVUX0tFWV0gICAgICAgIFRlc3RuZXRzIGhhdmUgc2FtZSB2YWx1ZVxuZm9ya0lkICAgICAgICAgc3JjL3NjcmlwdC9pbnRlcnByZXRlci5oICBGT1JLSURfKlxuXG4qL1xuXG5jb25zdCBjb2lucyA9IHtcbiAgQkNIOiAnYmNoJyxcbiAgQlNWOiAnYnN2JyxcbiAgQlRDOiAnYnRjJyxcbiAgQlRHOiAnYnRnJyxcbiAgTFRDOiAnbHRjJyxcbiAgWkVDOiAnemVjJyxcbiAgREFTSDogJ2Rhc2gnXG59XG5cbmZ1bmN0aW9uIGdldERlZmF1bHRCaXAzMk1haW5uZXQgKCkge1xuICByZXR1cm4ge1xuICAgIC8vIGJhc2U1OCAneHB1YidcbiAgICBwdWJsaWM6IDB4MDQ4OGIyMWUsXG4gICAgLy8gYmFzZTU4ICd4cHJ2J1xuICAgIHByaXZhdGU6IDB4MDQ4OGFkZTRcbiAgfVxufVxuXG5mdW5jdGlvbiBnZXREZWZhdWx0QmlwMzJUZXN0bmV0ICgpIHtcbiAgcmV0dXJuIHtcbiAgICAvLyBiYXNlNTggJ3RwdWInXG4gICAgcHVibGljOiAweDA0MzU4N2NmLFxuICAgIC8vIGJhc2U1OCAndHBydidcbiAgICBwcml2YXRlOiAweDA0MzU4Mzk0XG4gIH1cbn1cblxubW9kdWxlLmV4cG9ydHMgPSB7XG5cbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL2JpdGNvaW4vYml0Y29pbi9ibG9iL21hc3Rlci9zcmMvdmFsaWRhdGlvbi5jcHBcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL2JpdGNvaW4vYml0Y29pbi9ibG9iL21hc3Rlci9zcmMvY2hhaW5wYXJhbXMuY3BwXG4gIGJpdGNvaW46IHtcbiAgICBtZXNzYWdlUHJlZml4OiAnXFx4MThCaXRjb2luIFNpZ25lZCBNZXNzYWdlOlxcbicsXG4gICAgYmVjaDMyOiAnYmMnLFxuICAgIGJpcDMyOiBnZXREZWZhdWx0QmlwMzJNYWlubmV0KCksXG4gICAgcHViS2V5SGFzaDogMHgwMCxcbiAgICBzY3JpcHRIYXNoOiAweDA1LFxuICAgIHdpZjogMHg4MCxcbiAgICBjb2luOiBjb2lucy5CVENcbiAgfSxcbiAgdGVzdG5ldDoge1xuICAgIG1lc3NhZ2VQcmVmaXg6ICdcXHgxOEJpdGNvaW4gU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiZWNoMzI6ICd0YicsXG4gICAgYmlwMzI6IGdldERlZmF1bHRCaXAzMlRlc3RuZXQoKSxcbiAgICBwdWJLZXlIYXNoOiAweDZmLFxuICAgIHNjcmlwdEhhc2g6IDB4YzQsXG4gICAgd2lmOiAweGVmLFxuICAgIGNvaW46IGNvaW5zLkJUQ1xuICB9LFxuXG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9CaXRjb2luLUFCQy9iaXRjb2luLWFiYy9ibG9iL21hc3Rlci9zcmMvdmFsaWRhdGlvbi5jcHBcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL0JpdGNvaW4tQUJDL2JpdGNvaW4tYWJjL2Jsb2IvbWFzdGVyL3NyYy9jaGFpbnBhcmFtcy5jcHBcbiAgYml0Y29pbmNhc2g6IHtcbiAgICBtZXNzYWdlUHJlZml4OiAnXFx4MThCaXRjb2luIFNpZ25lZCBNZXNzYWdlOlxcbicsXG4gICAgYmlwMzI6IGdldERlZmF1bHRCaXAzMk1haW5uZXQoKSxcbiAgICBwdWJLZXlIYXNoOiAweDAwLFxuICAgIHNjcmlwdEhhc2g6IDB4MDUsXG4gICAgd2lmOiAweDgwLFxuICAgIGNvaW46IGNvaW5zLkJDSCxcbiAgICBmb3JrSWQ6IDB4MDBcbiAgfSxcbiAgYml0Y29pbmNhc2hUZXN0bmV0OiB7XG4gICAgbWVzc2FnZVByZWZpeDogJ1xceDE4Qml0Y29pbiBTaWduZWQgTWVzc2FnZTpcXG4nLFxuICAgIGJpcDMyOiBnZXREZWZhdWx0QmlwMzJUZXN0bmV0KCksXG4gICAgcHViS2V5SGFzaDogMHg2ZixcbiAgICBzY3JpcHRIYXNoOiAweGM0LFxuICAgIHdpZjogMHhlZixcbiAgICBjb2luOiBjb2lucy5CQ0hcbiAgfSxcblxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vQlRDR1BVL0JUQ0dQVS9ibG9iL21hc3Rlci9zcmMvdmFsaWRhdGlvbi5jcHBcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL0JUQ0dQVS9CVENHUFUvYmxvYi9tYXN0ZXIvc3JjL2NoYWlucGFyYW1zLmNwcFxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vQlRDR1BVL0JUQ0dQVS9ibG9iL21hc3Rlci9zcmMvc2NyaXB0L2ludGVycHJldGVyLmhcbiAgYml0Y29pbmdvbGQ6IHtcbiAgICBtZXNzYWdlUHJlZml4OiAnXFx4MThCaXRjb2luIEdvbGQgU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiZWNoMzI6ICdidGcnLFxuICAgIGJpcDMyOiBnZXREZWZhdWx0QmlwMzJNYWlubmV0KCksXG4gICAgcHViS2V5SGFzaDogMHgyNixcbiAgICBzY3JpcHRIYXNoOiAweDE3LFxuICAgIHdpZjogMHg4MCxcbiAgICBmb3JrSWQ6IDc5LFxuICAgIGNvaW46IGNvaW5zLkJUR1xuICB9LFxuICBiaXRjb2luZ29sZFRlc3RuZXQ6IHtcbiAgICBtZXNzYWdlUHJlZml4OiAnXFx4MThCaXRjb2luIEdvbGQgU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiZWNoMzI6ICd0YnRnJyxcbiAgICBiaXAzMjogZ2V0RGVmYXVsdEJpcDMyVGVzdG5ldCgpLFxuICAgIHB1YktleUhhc2g6IDExMSxcbiAgICBzY3JpcHRIYXNoOiAxOTYsXG4gICAgd2lmOiAweGVmLFxuICAgIGZvcmtJZDogNzksXG4gICAgY29pbjogY29pbnMuQlRHXG4gIH0sXG5cbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL2JpdGNvaW4tc3YvYml0Y29pbi1zdi9ibG9iL21hc3Rlci9zcmMvdmFsaWRhdGlvbi5jcHBcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL2JpdGNvaW4tc3YvYml0Y29pbi1zdi9ibG9iL21hc3Rlci9zcmMvY2hhaW5wYXJhbXMuY3BwXG4gIGJpdGNvaW5zdjoge1xuICAgIG1lc3NhZ2VQcmVmaXg6ICdcXHgxOEJpdGNvaW4gU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiaXAzMjogZ2V0RGVmYXVsdEJpcDMyTWFpbm5ldCgpLFxuICAgIHB1YktleUhhc2g6IDB4MDAsXG4gICAgc2NyaXB0SGFzaDogMHgwNSxcbiAgICB3aWY6IDB4ODAsXG4gICAgY29pbjogY29pbnMuQlNWLFxuICAgIGZvcmtJZDogMHgwMFxuICB9LFxuICBiaXRjb2luc3ZUZXN0bmV0OiB7XG4gICAgbWVzc2FnZVByZWZpeDogJ1xceDE4Qml0Y29pbiBTaWduZWQgTWVzc2FnZTpcXG4nLFxuICAgIGJpcDMyOiBnZXREZWZhdWx0QmlwMzJUZXN0bmV0KCksXG4gICAgcHViS2V5SGFzaDogMHg2ZixcbiAgICBzY3JpcHRIYXNoOiAweGM0LFxuICAgIHdpZjogMHhlZixcbiAgICBjb2luOiBjb2lucy5CU1ZcbiAgfSxcblxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vZGFzaHBheS9kYXNoL2Jsb2IvbWFzdGVyL3NyYy92YWxpZGF0aW9uLmNwcFxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vZGFzaHBheS9kYXNoL2Jsb2IvbWFzdGVyL3NyYy9jaGFpbnBhcmFtcy5jcHBcbiAgZGFzaDoge1xuICAgIG1lc3NhZ2VQcmVmaXg6ICdcXHgxOURhcmtDb2luIFNpZ25lZCBNZXNzYWdlOlxcbicsXG4gICAgYmlwMzI6IGdldERlZmF1bHRCaXAzMk1haW5uZXQoKSxcbiAgICBwdWJLZXlIYXNoOiAweDRjLFxuICAgIHNjcmlwdEhhc2g6IDB4MTAsXG4gICAgd2lmOiAweGNjLFxuICAgIGNvaW46IGNvaW5zLkRBU0hcbiAgfSxcbiAgZGFzaFRlc3Q6IHtcbiAgICBtZXNzYWdlUHJlZml4OiAnXFx4MTlEYXJrQ29pbiBTaWduZWQgTWVzc2FnZTpcXG4nLFxuICAgIGJpcDMyOiBnZXREZWZhdWx0QmlwMzJUZXN0bmV0KCksXG4gICAgcHViS2V5SGFzaDogMHg4YyxcbiAgICBzY3JpcHRIYXNoOiAweDEzLFxuICAgIHdpZjogMHhlZixcbiAgICBjb2luOiBjb2lucy5EQVNIXG4gIH0sXG5cbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL2xpdGVjb2luLXByb2plY3QvbGl0ZWNvaW4vYmxvYi9tYXN0ZXIvc3JjL3ZhbGlkYXRpb24uY3BwXG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9saXRlY29pbi1wcm9qZWN0L2xpdGVjb2luL2Jsb2IvbWFzdGVyL3NyYy9jaGFpbnBhcmFtcy5jcHBcbiAgbGl0ZWNvaW46IHtcbiAgICBtZXNzYWdlUHJlZml4OiAnXFx4MTlMaXRlY29pbiBTaWduZWQgTWVzc2FnZTpcXG4nLFxuICAgIGJlY2gzMjogJ2x0YycsXG4gICAgYmlwMzI6IGdldERlZmF1bHRCaXAzMk1haW5uZXQoKSxcbiAgICBwdWJLZXlIYXNoOiAweDMwLFxuICAgIHNjcmlwdEhhc2g6IDB4MzIsXG4gICAgd2lmOiAweGIwLFxuICAgIGNvaW46IGNvaW5zLkxUQ1xuICB9LFxuICBsaXRlY29pblRlc3Q6IHtcbiAgICBtZXNzYWdlUHJlZml4OiAnXFx4MTlMaXRlY29pbiBTaWduZWQgTWVzc2FnZTpcXG4nLFxuICAgIGJlY2gzMjogJ3RsdGMnLFxuICAgIGJpcDMyOiBnZXREZWZhdWx0QmlwMzJUZXN0bmV0KCksXG4gICAgcHViS2V5SGFzaDogMHg2ZixcbiAgICBzY3JpcHRIYXNoOiAweDNhLFxuICAgIHdpZjogMHhlZixcbiAgICBjb2luOiBjb2lucy5MVENcbiAgfSxcblxuICAvLyBodHRwczovL2dpdGh1Yi5jb20vemNhc2gvemNhc2gvYmxvYi9tYXN0ZXIvc3JjL3ZhbGlkYXRpb24uY3BwXG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL21hc3Rlci9zcmMvY2hhaW5wYXJhbXMuY3BwXG4gIHpjYXNoOiB7XG4gICAgbWVzc2FnZVByZWZpeDogJ1xceDE4WkNhc2ggU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiaXAzMjogZ2V0RGVmYXVsdEJpcDMyTWFpbm5ldCgpLFxuICAgIHB1YktleUhhc2g6IDB4MWNiOCxcbiAgICBzY3JpcHRIYXNoOiAweDFjYmQsXG4gICAgd2lmOiAweDgwLFxuICAgIC8vIFRoaXMgcGFyYW1ldGVyIHdhcyBpbnRyb2R1Y2VkIGluIHZlcnNpb24gMyB0byBhbGxvdyBzb2Z0IGZvcmtzLCBmb3IgdmVyc2lvbiAxIGFuZCAyIHRyYW5zYWN0aW9ucyB3ZSBhZGQgYVxuICAgIC8vIGR1bW15IHZhbHVlLlxuICAgIGNvbnNlbnN1c0JyYW5jaElkOiB7XG4gICAgICAxOiAweDAwLFxuICAgICAgMjogMHgwMCxcbiAgICAgIDM6IDB4NWJhODFiMTksXG4gICAgICAvLyA0OiAweDc2YjgwOWJiIChvbGQgU2FwbGluZyBicmFuY2ggaWQpLiBCbG9zc29tIGJyYW5jaCBpZCBiZWNvbWVzIGVmZmVjdGl2ZSBhZnRlciBibG9jayA2NTM2MDBcbiAgICAgIC8vIDQ6IDB4MmJiNDBlNjBcbiAgICAgIC8vIDQ6IDB4ZjViOTIzMGIgKEhlYXJ0d29vZCBicmFuY2ggaWQsIHNlZSBodHRwczovL3ppcHMuei5jYXNoL3ppcC0wMjUwKVxuICAgICAgNDogMHhlOWZmNzVhNiAvLyAoQ2Fub3B5IGJyYW5jaCBpZCwgc2VlIGh0dHBzOi8vemlwcy56LmNhc2gvemlwLTAyNTEpXG4gICAgfSxcbiAgICBjb2luOiBjb2lucy5aRUNcbiAgfSxcbiAgemNhc2hUZXN0OiB7XG4gICAgbWVzc2FnZVByZWZpeDogJ1xceDE4WkNhc2ggU2lnbmVkIE1lc3NhZ2U6XFxuJyxcbiAgICBiaXAzMjogZ2V0RGVmYXVsdEJpcDMyVGVzdG5ldCgpLFxuICAgIHB1YktleUhhc2g6IDB4MWQyNSxcbiAgICBzY3JpcHRIYXNoOiAweDFjYmEsXG4gICAgd2lmOiAweGVmLFxuICAgIGNvbnNlbnN1c0JyYW5jaElkOiB7XG4gICAgICAxOiAweDAwLFxuICAgICAgMjogMHgwMCxcbiAgICAgIDM6IDB4NWJhODFiMTksXG4gICAgICAvLyA0OiAweDc2YjgwOWJiIChvbGQgU2FwbGluZyBicmFuY2ggaWQpXG4gICAgICAvLyA0OiAweDJiYjQwZTYwXG4gICAgICAvLyA0OiAweGY1YjkyMzBiIChIZWFydHdvb2QgYnJhbmNoIGlkLCBzZWUgaHR0cHM6Ly96aXBzLnouY2FzaC96aXAtMDI1MClcbiAgICAgIDQ6IDB4ZTlmZjc1YTYgLy8gKENhbm9weSBicmFuY2ggaWQsIHNlZSBodHRwczovL3ppcHMuei5jYXNoL3ppcC0wMjUxKVxuICAgIH0sXG4gICAgY29pbjogY29pbnMuWkVDXG4gIH1cbn1cbiJdfQ==