package com.jsocketstu.clientserver;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HTTPSServer {

//	private static final String JKS_FILE = "c:\\mde\\fdsa.jks";
	private static final String JKS_FILE = "c:\\mde\\mytestkey.jks";
//	private static final String PASSWORD = "4654";
	private static final String PASSWORD = "password";

	private static final String TYPE = "JKS";

	private static final Logger LOG = LogManager.getLogger(HTTPSServer.class);

	private int port = 9999;
	private boolean isServerDone = false;

	public static void main(String[] args) {
		LOG.debug("Debug Message Logged !!!");
		LOG.info("Info Message Logged !!!");
		LOG.trace("trace Message Logged !!!");

		HTTPSServer server = new HTTPSServer();
		server.start();
	}

	HTTPSServer() {
	}

	HTTPSServer(int port) {
		this.port = port;
	}

	private SSLContext createSSLContext() {
		LOG.info("===========================================================================================");
		LOG.info("Inicializando SSLContext");
		try {
			KeyStore keyStore = KeyStore.getInstance(TYPE);
			keyStore.load(new FileInputStream(JKS_FILE), PASSWORD.toCharArray());

			LOG.info("===========================================================================================");
			LOG.info("Criando KeyManager SSLContext");

			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
			keyManagerFactory.init(keyStore, PASSWORD.toCharArray());
			KeyManager[] keyManager = keyManagerFactory.getKeyManagers();

			LOG.info("===========================================================================================");
			LOG.info("Criando TrustManager");
			TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
			trustManagerFactory.init(keyStore);
			TrustManager[] trustManager = trustManagerFactory.getTrustManagers();

			LOG.info("===========================================================================================");
			LOG.info("Inicializando o SSLContext");

			SSLContext sslContext = SSLContext.getInstance("TLSv1");
			sslContext.init(keyManager, trustManager, null);

			LOG.info("===========================================================================================");
			LOG.info("SSLContext inicializado");
			return sslContext;
		} catch (Exception e) {
			LOG.info("===========================================================================================");
			LOG.error(e.getMessage());

		}

		return null;
	}

	// Start Server
	public void start() {
		SSLContext sslContext = this.createSSLContext();

		try {
			// Create Server Socket Factory
			SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

			// Create Server Socket
			SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(this.port);

			LOG.info("<< SSL Server Started >>");
			while (!isServerDone) {
				SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();

				// Start the server thread
				new ServerThread(sslSocket).start();
			}

		} catch (NullPointerException | IOException e) {
			LOG.error(e.getMessage());
		}
	}

	// Thread handling the Socket from Client
	static class ServerThread extends Thread {

		private SSLSocket sslSocket = null;

		ServerThread(SSLSocket sslSocket) {
			this.sslSocket = sslSocket;
		}

		public void run() {
			sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

			try {
				// Start Handshake
				sslSocket.startHandshake();

				// Get session after the connection is established
				SSLSession sslSession = sslSocket.getSession();

				System.out.println("SSLSession :");
				System.out.println("\tProtocol : " + sslSession.getProtocol());
				System.out.println("\tCipher suite : " + sslSession.getCipherSuite());

				// Start handling Application Content
				InputStream inputStream = sslSocket.getInputStream();
				OutputStream outputStream = sslSocket.getOutputStream();

				BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
				PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));

				String line = null;
				while ((line = bufferedReader.readLine()) != null) {
					System.out.println("Inut : " + line);

					if (line.trim().isEmpty()) {
						break;
					}
				}

				// Write data
				printWriter.print("HTTP/1.1 200\r\n");
				printWriter.flush();

				sslSocket.close();
			} catch (NullPointerException | IOException e) {
				LOG.error(e.getMessage());
			}
		}
	}
}