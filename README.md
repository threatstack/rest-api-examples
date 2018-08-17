# Threatstack Rest Api Example Clients

This repository provides examples of the Threat Stack v2 API. 
The examples center on setting up Hawk authentication.

All sample projects require the same environment variables to be set:
  - `TS_USER_ID` - User id of the api key holder
  - `TS_API_KEY` - API key for the user specified by TS_USER_ID
  - `TS_ORGANIZATION_ID` - Organization id of the organization to access

## Python
Install Python 3 to run the python example.
To install dependencies, run `pip`:
```bash
pip install -r requirements.txt
```

Run the following python command using the environment variables:
```bash
TS_USER_ID=x TS_ORGANIZATION_ID=x TS_API_KEY=x python3 example.py
```

## Ruby
Disclaimer: Ruby's HAWK implementation is no longer maintained. You may want to consider a different language.

Before you can install the dependencies, you must install Ruby and bundler:
To install dependencies, run `bundle`:
```bash
bundle install
```

Run the following ruby command using the environment variables:
```bash
TS_USER_ID=x TS_ORGANIZATION_ID=x TS_API_KEY=x ruby example.rb
```

NOTE: The Faraday HTTP client used in this example reorders the query string parameters into alphabetical order before sending them to the server.
If you do not specify the parameters in your query string in alphabetical order, then the request to the server will fail with a 401 Unauthorized.
This is because the Auth header that the client computes will be different than what the server computes.

## Java
Before you can install the dependencies, you must install Java and Maven 3.
To install dependencies, run `mvn`:
```bash
mvn compile
```

Run the following mvn command using the environment variables:
```bash
TS_USER_ID=x TS_ORGANIZATION_ID=x TS_API_KEY=x mvn exec:java
```

## Node JS
Before you can install the dependencies, you must install Node and npm.
To install dependencies, run `npm`:
```bash
npm install
```

Run the following node command using the environment variables:
```bash
TS_USER_ID=x TS_ORGANIZATION_ID=x TS_API_KEY=x node example.js
```
