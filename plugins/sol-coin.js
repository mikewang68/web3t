// Generated by LiveScript 1.6.0
(function(){
  var mainnetConfig, testnetConfig, devnetConfig, mainnet, testnet, devnet, color, type, walletIndex, enabled, name, token, nickname, market, image, usdInfo, out$ = typeof exports != 'undefined' && exports || this;
  mainnetConfig = {
    disabled: false,
    decimals: 9,
    txFee: '0.000005',
    txFeeOptions: {
      auto: '0.000005',
      cheap: '0.000005'
    },
    messagePrefix: 'Ethereum',
    mask: '3000000000000000000000000000000000',
    api: {
      provider: 'solana',
      web3Provider: 'https://explorer.velas.com/rpc',
      url: 'https://native.velas.com',
      apiUrl: 'https://api.velas.com',
      validatorsBackend: 'https://validators.mainnet.velas.com',
    },
    HomeBridge: "0x56454c41532d434841494e000000000053574150",
    networks: {
      vlx_evm: {
        id: "vlx_evm",
        name: "Sino EVM",
        referTo: "vlx_evm"
      },
      vlx2: {
        id: "vlx2",
        name: "Sino Legacy",
        referTo: "vlx2"
      }
    },
    group: 'Sino'
  };
  testnetConfig = {
    decimals: 9,
    txFee: '0.000005',
    txFeeOptions: {
      auto: '0.000005',
      cheap: '0.000005'
    },
    messagePrefix: 'Ethereum',
    mask: '3000000000000000000000000000000000',
    api: {
      provider: 'solana',
      web3Provider: 'https://api.testnet.velas.com/rpc',
      url: 'https://native.velas.com',
      apiUrl: 'https://explorer.testnet.velas.com/api',
      validatorsBackend: 'https://validators.testnet.velas.com',
      cluster: 'testnet'
    },
    HomeBridge: "0x56454c41532d434841494e000000000053574150",
    networks: {
      vlx_evm: {
        id: "vlx_evm",
        name: "Velas EVM",
        referTo: "vlx_evm"
      },
      vlx2: {
        id: "vlx2",
        name: "Velas Legacy",
        referTo: "vlx2"
      }
    },
    group: 'Sino'
  };
  devnetConfig = {
    decimals: 9,
    txFee: '0.000005',
    txFeeOptions: {
      auto: '0.000005',
      cheap: '0.000005'
    },
    messagePrefix: 'Ethereum',
    mask: '3000000000000000000000000000000000',
    api: {
      provider: 'solana',
      web3Provider: 'https://api.devnet.velas.com',
      url: 'https://native.velas.com',
      apiUrl: 'https://api.devnet.velas.com/api',
      cluster: 'devnet'
    },
    networks: {
      legacy: {
        id: "legacy",
        name: "Velas",
        referTo: "vlx2"
      },
      evm: {
        id: "evm",
        name: "Velas EVM",
        referTo: "vlx_evm"
      }
    },
    group: 'Sino'
  };
  out$.mainnet = mainnet = mainnetConfig;
  out$.testnet = testnet = testnetConfig;
  out$.devnet = devnet = devnetConfig;
  out$.color = color = '#9E4FEB';
  out$.type = type = 'coin';
  out$.walletIndex = walletIndex = 0;
  out$.enabled = enabled = true;
  out$.name = name = 'Sino Native';
  out$.token = token = 'vlx_native';
  out$.nickname = nickname = 'sor';
  out$.market = market = "https://api.coinmarketcap.com/data-api/v3/cryptocurrency/detail/chart?id=4747&range=ALL";
  out$.image = image = 'data:image/png;base64,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';
  out$.usdInfo = usdInfo = 'url(https://explorer.velas.com/ticker).price_usd';
}).call(this);
