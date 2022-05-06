package com.jsocketstu.clientserver;

import java.net.URL;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

public class HTTPSClientB {
// Disable the hostname verification for demo purpose
	static {
		HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
			public boolean verify(String s, SSLSession sslSession) {
				return true;
			}
		});
	}

	public static void main(String[] args) {
// Initialize configuration
		System.setProperty("javax.net.ssl.trustStore", "test.jks");
		System.setProperty("javax.net.ssl.trustStoreType", "jks");

		try {
			URL url = new URL("https://127.0.0.1:9999");
			HttpsURLConnection client = (HttpsURLConnection) url.openConnection();

			System.out.println("RETURN : " + client.getResponseCode());
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
}