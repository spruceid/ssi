const taquito = require('@taquito/taquito');

const signer = require('@taquito/signer');
// signer.importKey("c6d196eea462e073e72da3366a19ff4e5134f3fa")

const Tezos = new taquito.TezosToolkit('https://api.tez.ie/rpc/delphinet');

const contract = require('../contract.michelson')

Tezos.setProvider({
  signer: new signer.InMemorySigner('c6d196eea462e073e72da3366a19ff4e5134f3fa'),
});

Tezos.contract.originate({
  code: contract,
  storage: {
    result: null,
    rotation_count: 0,
    active_key: 'tz1Z3yNumnSFoHtMsMPAkiCqDQpTcnw7fk1s',
    verification_method: 'tz1Z3yNumnSFoHtMsMPAkiCqDQpTcnw7fk1s',
    service: {
      type: 'TezosDiscoveryService',
      service_endpoint: 'tezos-storage://KT1QDFEu8JijYbsJqzoXq7mKvfaQQamHD1kX/listing'
    }
  }
}).then(originationOp => {
  process.stdout.write(`Waiting for confirmation of origination for ${originationOp.contractAddress}...`);
  return originationOp.contract()
}).then(contract => {
  process.stdout.write(`Origination completed.`);
}).catch(error => process.stdout.write(`Error: ${JSON.stringify(error, null, 2)}`));
