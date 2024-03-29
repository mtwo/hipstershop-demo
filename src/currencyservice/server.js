/*
 * Copyright 2018 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require('@google-cloud/profiler').start({
  serviceContext: {
      service: 'currencyservice',
      version: '1.0.0'
  }
});
 require('@google-cloud/trace-agent').start();
 require('@google-cloud/debug-agent').start({
  serviceContext: {
    service: 'currencyservice',
    version: '1.0.0'
  }
})

const path = require('path');
const grpc = require('grpc');
const request = require('request');
const xml2js = require('xml2js');

const PROTO_PATH = path.join(__dirname, './proto/demo.proto');
const PORT = 7000;
const DATA_URL = 'http://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml';
const shopProto = grpc.load(PROTO_PATH).hipstershop;

/**
 * Helper function that gets currency data from an XML webpage
 * Uses public data from European Central Bank
 */
let _data;
function _getCurrencyData (callback) {
  if (!_data) {
    console.log('Fetching currency data...');
    request(DATA_URL, (err, res) => {
      if (err) {
        throw new Error(`Error getting data: ${err}`);
      }

      const body = res.body.split('\n').slice(7, -2).join('\n');
      xml2js.parseString(body, (err, resJs) => {
        if (err) {
          throw new Error(`Error parsing HTML: ${err}`);
        }

        const array = resJs['Cube']['Cube'].map(x => x['$']);
        const results = array.reduce((acc, x) => {
          acc[x['currency']] = x['rate'];
          return acc;
        }, { 'EUR': '1.0' });
        _data = results;
        callback(_data);
      });
    });
  } else {
    callback(_data);
  }
}

/**
 * Helper function that handles decimal/fractional carrying
 */
function _carry (amount) {
  const fractionSize = Math.pow(10, 9);
  amount.nanos += (amount.units % 1) * fractionSize;
  amount.units = Math.floor(amount.units) + Math.floor(amount.nanos / fractionSize);
  amount.nanos = amount.nanos % fractionSize;
  return amount;
}

/**
 * Lists the supported currencies
 */
function getSupportedCurrencies (call, callback) {
  console.log('Getting supported currencies...');
  _getCurrencyData((data) => {
    callback(null, {currency_codes: Object.keys(data)});
  });
}

/**
 * Converts between currencies
 */
function convert (call, callback) {
  console.log('received conversion request');
  try {
    _getCurrencyData((data) => {
      const request = call.request;

      // Convert: from_currency --> EUR
      const from = request.from;
      const euros = _carry({
        units: from.units / data[from.currency_code],
        nanos: from.nanos / data[from.currency_code]
      });

      euros.nanos = Math.round(euros.nanos);

      // Convert: EUR --> to_currency
      const result = _carry({
        units: euros.units * data[request.to_code],
        nanos: euros.nanos * data[request.to_code]
      });

      result.units = Math.floor(result.units)
      result.nanos = Math.floor(result.nanos)
      result.currency_code = request.to_code;

      console.log(`conversion request successful`);
      callback(null, result);
    });
  } catch (err) {
    console.error('conversion request failed.');
    console.error(err);
    callback(err.message);
  }
}

/**
 * Starts an RPC server that receives requests for the
 * CurrencyConverter service at the sample server port
 */
function main () {
  console.log(`Starting gRPC server on port ${PORT}...`);
  const server = new grpc.Server();
  server.addService(shopProto.CurrencyService.service, {getSupportedCurrencies, convert});
  server.bind(`0.0.0.0:${PORT}`, grpc.ServerCredentials.createInsecure());
  server.start();
}

main();
