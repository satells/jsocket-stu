package com.jsocketstu.cert;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

public class Certificate {

	private static final String ALIAS = "mykey";
	private static final String TYPE = "JKS";
	private static final String PASSWORD = "password";
	private static final String JKS_FILE = "c:\\mde\\mytestkey.jks";

	public static void main(String[] args) {
		Certificate certificate = new Certificate();

		certificate.createJKSkeystore();
		certificate.storePrivateKey();
		certificate.storeCertificate();
		certificate.loadingPrivateKey();
		certificate.loadingCertificate();

	}

	private void createJKSkeystore() {
		try {
			KeyStore keyStore = KeyStore.getInstance(TYPE);
			keyStore.load(null, null);

			keyStore.store(new FileOutputStream(JKS_FILE), PASSWORD.toCharArray());
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void storePrivateKey() {
		try {
			KeyStore keyStore = KeyStore.getInstance(TYPE);
			keyStore.load(new FileInputStream(JKS_FILE), PASSWORD.toCharArray());

			CertAndKeyGen gen = new CertAndKeyGen("RSA", "SHA1WithRSA");
			gen.generate(1024);

			Key key = gen.getPrivateKey();
			X509Certificate cert = gen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 3600);

			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = cert;

			keyStore.setKeyEntry(ALIAS, key, PASSWORD.toCharArray(), chain);

			keyStore.store(new FileOutputStream(JKS_FILE), PASSWORD.toCharArray());
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void storeCertificate() {
		try {
			KeyStore keyStore = KeyStore.getInstance(TYPE);
			keyStore.load(new FileInputStream(JKS_FILE), PASSWORD.toCharArray());

			CertAndKeyGen gen = new CertAndKeyGen("RSA", "SHA1WithRSA");
			gen.generate(1024);

			X509Certificate cert = gen.getSelfCertificate(new X500Name("CN=SINGLE_CERTIFICATE"), (long) 365 * 24 * 3600);

			keyStore.setCertificateEntry("single_cert", cert);

			keyStore.store(new FileOutputStream(JKS_FILE), PASSWORD.toCharArray());
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void loadingPrivateKey() {
		try {
			KeyStore keyStore = KeyStore.getInstance(TYPE);
			keyStore.load(new FileInputStream(JKS_FILE), PASSWORD.toCharArray());

			Key key = keyStore.getKey(ALIAS, PASSWORD.toCharArray());
//		          System.out.println("Private key : "+key.toString());   //You will get a NullPointerException if you uncomment this line

			java.security.cert.Certificate[] chain = keyStore.getCertificateChain(ALIAS);
			for (java.security.cert.Certificate cert : chain) {
				System.out.println(cert.toString());
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void loadingCertificate() {
		try {
			KeyStore keyStore = KeyStore.getInstance(TYPE);
			keyStore.load(new FileInputStream(JKS_FILE), PASSWORD.toCharArray());

			java.security.cert.Certificate cert = keyStore.getCertificate("single_cert");

			System.out.println(cert.toString());
		} catch (Exception ex) {
			ex.printStackTrace();
		}

	}

}
