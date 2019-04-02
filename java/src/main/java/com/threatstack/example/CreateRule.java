package com.threatstack.example;

import com.google.gson.*;
import com.google.common.io.BaseEncoding;

import com.wealdtech.hawk.HawkClient;
import com.wealdtech.hawk.HawkCredentials;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.security.MessageDigest;
import java.util.*;

public class CreateRule {
    public static void main(String[] args) {
        String HOST = getEnvOrDefault("TS_HOST", "api.threatstack.com");
        String USER_ID = getEnvOrDefault("TS_USER_ID", null);
        String ORGANIZATION_ID = getEnvOrDefault("TS_ORGANIZATION_ID", null);
        String API_KEY = getEnvOrDefault("TS_API_KEY", null);
        String RULESET_ID = getEnvOrDefault("TS_RULESET_ID", null);
        String javaVersion = getEnvOrDefault("java.version", "unknown");

        String BASE_PATH = "https://" + HOST;
        String URI_PATH = "/v2/rulesets/" + RULESET_ID + "/rules";

        HawkCredentials hawkCredentials = new HawkCredentials.Builder()
                .keyId(USER_ID)
                .key(API_KEY)
                .algorithm(HawkCredentials.Algorithm.SHA256)
                .build();

        //Define the data that we wish to post
        String[] aggregateFields = new String[2];
        aggregateFields[0] = "user";
        aggregateFields[1] = "session";

        String[] suppressions = new String[1];
        suppressions[0] = "user = 'alice' OR user = 'bob'";

        Dictionary ruleData = new Hashtable();
        ruleData.put("name", "API Test Rule: Sudo Usage");
        ruleData.put("title", "API Test Rule: Sudo Usage");
        ruleData.put("type", "host");
        ruleData.put("severityOfAlerts", 2);
        ruleData.put("alertDescription", "This rule was created as a test of the Threat Stack REST API. It monitors for usage of sudo");
        ruleData.put("aggregateFields", aggregateFields);
        ruleData.put("filter", "command = 'sudo'");
        ruleData.put("window", 3600);
        ruleData.put("threshold", 1);
        ruleData.put("suppressions", suppressions);
        ruleData.put("enabled", true);

        //Convert that object to a JSON string
        Gson gson = new Gson();
        String postData = gson.toJson(ruleData);

        try {
            HawkClient hawkClient = new HawkClient.Builder().credentials(hawkCredentials).build();
            URL url = new URL(BASE_PATH + URI_PATH);

            //Hash the body that we wish to post
            final StringBuilder sb = new StringBuilder(1024);
            sb.append("hawk.");
            sb.append("1");
            sb.append(".payload\n");
            sb.append("application/json");
            sb.append('\n');
            sb.append(postData);
            sb.append('\n');
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String hashedPostData = BaseEncoding.base64().encode(digest.digest(sb.toString().getBytes("UTF-8")));

            String hawkHeader = hawkClient.generateAuthorizationHeader(url.toURI(), "POST", hashedPostData, ORGANIZATION_ID, null, null);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.addRequestProperty("Authorization", hawkHeader);
            conn.addRequestProperty("Content-Type", "application/json");
            conn.addRequestProperty("User-Agent", "");
            
            conn.setDoOutput(true);
            OutputStream os = conn.getOutputStream();
            OutputStreamWriter wr = new OutputStreamWriter(os, "UTF-8");
            wr.write(postData);
            wr.close();
            os.close();

            String responseBody = readResponseAndClose(conn);

            System.out.println(responseBody);
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    private static String getEnvOrDefault(String key, String defaultValue) {
        String res = System.getenv(key);
        if (res == null) {
            if (defaultValue == null) {
                throw new RuntimeException("Environment variable '" + key + "' must be provided");
            }
            return defaultValue;
        }

        return res;
    }

    private static String readResponseAndClose(HttpURLConnection conn) throws IOException {
        conn.connect();
        InputStream inputStream = conn.getInputStream();
        BufferedReader rd = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder result = new StringBuilder();
        String line;
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }
        rd.close();
        conn.disconnect();
        return result.toString();
    }
}
