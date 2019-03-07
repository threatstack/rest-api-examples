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

Examples have been removed, but leaving a signpost here for readers.


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
