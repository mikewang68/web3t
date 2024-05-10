// Generated by LiveScript 1.6.0
(function(){
  var mainnet, testnet, devnet, color, type, enabled, name, token, nickname, market, image, usdInfo, out$ = typeof exports != 'undefined' && exports || this;
  out$.mainnet = mainnet = {
    disabled: false,
    decimals: 18,
    txFee: '0.002',
    txFeeOptions: {
      auto: '0.002',
      cheap: '0.002'
    },
    /*
    api: {
      provider: 'velas_evm',
      apiUrl: 'https://evmexplorer.velas.com/api',
      web3Provider: 'https://evmexplorer.velas.com/rpc',
      url: 'https://evmexplorer.velas.com'
    },
    */
    api: {
      provider: 'velas_evm',
      apiUrl: 'http://192.168.101.101:8899',
      web3Provider: 'http://192.168.101.101:8899',
      url: 'http://192.168.101.101:8899'
    },
    HOME_BRIDGE: "0x38E20F6224449eCB50A81188147cbf990a00eA44",
    FOREIGN_BRIDGE: "0xA5D512085006867974405679f2c9476F4F7Fa903",
    HECO_SWAP__HOME_BRIDGE: "0xa480B124990a262Cc1e4937e2f6084FEe75e781B",
    BSC_SWAP__HOME_BRIDGE: "0x24AE61B4a880573fc190a05A407033DA4cd30434",
    EVM_TO_NATIVE_BRIDGE: "0x56454c41532d434841494e000000000053574150",
    networks: {
      vlx_native: {
        id: "vlx_native",
        name: "Sino Native",
        referTo: "vlx_native"
      },
      vlx_erc20: {
        id: "vlx_erc20",
        name: "Ethereum (VLX ERC20)",
        referTo: "vlx_erc20"
      },
      bsc_vlx: {
        id: "bsc_vlx",
        name: "Binance Smart Chain (VLX BEP20)",
        referTo: "bsc_vlx"
      },
      vlx_huobi: {
        id: "vlx_huobi",
        name: "Huobi ECO Chain (VLX HRC20)",
        referTo: "vlx_huobi"
      },
      vlx2: {
        id: "vlx2",
        name: "Sino Legacy",
        referTo: "vlx2"
      }
    },
    group: 'Sino'
  };
  out$.testnet = testnet = {
    disabled: false,
    decimals: 18,
    txFee: '0.000001',
    txFeeOptions: {
      auto: '0.000020',
      cheap: '0.000020'
    },
    api: {
      provider: 'velas_evm',
      web3Provider: 'https://evmexplorer.testnet.velas.com/rpc',
      url: 'https://evmexplorer.testnet.velas.com',
      apiUrl: 'https://evmexplorer.testnet.velas.com/api'
    },
    HOME_BRIDGE: "0x57C7f6CD50a432943F40F987a1448181D5B11307",
    FOREIGN_BRIDGE: "0xBDeDd09D5283fB38EFF898E3859AbAE96B712aF9",
    ERC20BridgeToken: "0xfEFF2e74eC612A288Ae55fe9F6e40c52817a1B6C",
    HECO_SWAP__HOME_BRIDGE: "0x8c8884Fdb4f9a6ca251Deef70670DF7C4c48045D",
    BSC_SWAP__HOME_BRIDGE: "0x97B7eb15cA5bFa82515f6964a3EAa1fE71DFB7A7",
    EVM_TO_NATIVE_BRIDGE: "0x56454c41532d434841494e000000000053574150",
    group: "Sino",
    networks: {
      vlx_native: {
        id: "vlx_native",
        name: "Sino Native",
        referTo: "vlx_native"
      },
      vlx_erc20: {
        id: "vlx_erc20",
        name: "Ethereum (VLX ERC20)",
        referTo: "vlx_erc20"
      },
      bsc_vlx: {
        id: "bsc_vlx",
        name: "Binance Smart Chain (VLX BEP20)",
        referTo: "bsc_vlx"
      },
      vlx_huobi: {
        id: "vlx_huobi",
        name: "Huobi ECO Chain (VLX HRC20)",
        referTo: "vlx_huobi"
      },
      vlx2: {
        id: "vlx2",
        name: "Sino Legacy",
        referTo: "vlx2"
      }
    }
  };
  out$.devnet = devnet = {
    disabled: false,
    decimals: 18,
    txFee: '0.000001',
    txFeeOptions: {
      auto: '0.000020',
      cheap: '0.000020'
    },
    api: {
      provider: 'velas_evm',
      web3Provider: 'https://explorer.devnet.velas.com/rpc',
      url: 'https://explorer.devnet.velas.com',
      apiUrl: 'https://explorer.devnet.velas.com/api'
    },
    group: "Sino",
    networks: {
      vlx_native: {
        id: "vlx_native",
        name: "Velas Native",
        referTo: "vlx_native"
      },
      vlx2: {
        id: "vlx2",
        name: "Velas",
        referTo: "vlx2"
      },
      vlx_erc20: {
        disabled: true,
        id: "vlx_erc20",
        name: "Velas ERC20",
        referTo: "vlx_erc20"
      }
    }
  };
  out$.color = color = '#9E4FEB';
  out$.type = type = 'coin';
  out$.enabled = enabled = true;
  out$.name = name = 'Sino EVM';
  out$.token = token = 'vlx_evm';
  out$.nickname = nickname = 'sor';
  out$.market = market = "https://api.coinmarketcap.com/data-api/v3/cryptocurrency/detail/chart?id=4747&range=ALL";
  out$.image = image = "data:image/png;base64,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";
  out$.usdInfo = usdInfo = "url(https://explorer.velas.com/ticker).price_usd";
}).call(this);
