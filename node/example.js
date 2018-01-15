"use strict";

const Hawk = require('hawk');
const https = require("https");

function makeRequest(options, onResult) {
  const req = https.request(options, function (res) {
    let output;
    res.setEncoding('utf8');

    res.on('data', function (chunk) {
      if (!output) {
        output = '';
      }
      output += chunk;
    });

    res.on('end', function () {
      onResult(null, {resp: res, content: output});
    });
  });

  req.on('error', function (err) {
    onResult(err);
  });

  req.end();
}

function getEnv(key, defaultValue) {
  let res = process.env[key];
  if (res === undefined && defaultValue !== undefined) {
    res = defaultValue;
  }
  if (res === undefined) {
    throw new Error(`Environment variable '${key}' must be set.`)
  }
  return res;
}

const organizationId = getEnv('TS_ORGANIZATION_ID');
const userId = getEnv('TS_USER_ID');
const apiKey = getEnv('TS_API_KEY');
const tsHost = getEnv('TS_HOST', 'api.threatstack.com');

const credentials = {
  id: userId,
  key: apiKey,
  algorithm: 'sha256'
};

const path = '/help/hawk/self-test';
const headerOptions = {
  credentials: credentials,
  ext: organizationId,
  contentType: "application/json"
};
const authorizationHeader = Hawk.client.header(`https://${tsHost}${path}`, 'GET', headerOptions);

makeRequest({
  host: tsHost,
  port: 443,
  path: path,
  method: 'GET',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': authorizationHeader.field
  }
}, function (err, result) {
  if (err) {
    console.log('Error making request', err);
    process.exit(1);
  }

  console.log(result.content);
  const isValid = Hawk.client.authenticate(result.resp, credentials, authorizationHeader.artifacts, { payload: result.content, required: true });
  console.log("Response was authenticated: " + isValid);
  process.exit(0);
});