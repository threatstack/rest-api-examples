package com.threatstack.example;

import com.wealdtech.hawk.HawkClient;
import com.wealdtech.hawk.HawkCredentials;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class Main {
    public static void main(String[] args) {
        String HOST = getEnvOrDefault("TS_HOST", "api.threatstack.com");
        String USER_ID = getEnvOrDefault("TS_USER_ID", null);
        String ORGANIZATION_ID = getEnvOrDefault("TS_ORGANIZATION_ID", null);
        String API_KEY = getEnvOrDefault("TS_API_KEY", null);
        String javaVersion = getEnvOrDefault("java.version", "unknown");

        String BASE_PATH = "https://" + HOST;
        String URI_PATH = "/help/hawk/self-test";

        HawkCredentials hawkCredentials = new HawkCredentials.Builder()
                .keyId(USER_ID)
                .key(API_KEY)
                .algorithm(HawkCredentials.Algorithm.SHA256)
                .build();
        try {
            HawkClient hawkClient = new HawkClient.Builder().credentials(hawkCredentials).build();
            URL url = new URL(BASE_PATH + URI_PATH);
            String hawkHeader = hawkClient.generateAuthorizationHeader(url.toURI(), "GET", null, ORGANIZATION_ID, null, null);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.addRequestProperty("Authorization", hawkHeader);
            conn.addRequestProperty("User-Agent", "Java/" + javaVersion);
            String responseBody = readResponseAndClose(conn);

            // There is no response authentication check here
            // because the Java library for HAWK does not support it.
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