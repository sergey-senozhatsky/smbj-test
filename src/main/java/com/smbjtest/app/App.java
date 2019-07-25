package com.smbjtest.app;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.Security;
import java.util.Map;
import java.util.HashSet;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.time.Instant;
import java.time.Duration;
import java.security.Provider;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.Share;
import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.smbj.io.InputStreamByteChunkProvider;
import com.hierynomus.mssmb2.SMB2GlobalCapability;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.security.bc.BCSecurityProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import org.bouncycastle.crypto.Digest;
import com.hierynomus.mssmb2.SMB2GlobalCapability;

class SMBTEST {
	static final String SERVER		= "SERVER";
	static final String DOMAIN		= "DOMAIN";
	static final String USER_NAME		= "USER_NAME";
	static final String PASSWORD		= "PASSWORD";
	static final String SHARE_NAME		= "SHARE_NAME";
	static final String REMOTE_RFILE	= "REMOTE_RFILE";
	static final String REMOTE_WFILE	= "REMOTE_WFILE";
	static final String LOCAL_RWFILE	= "LOCAL_RWFILE";
	static final String SMB_VERS		= "SMB_VERS";
	static final String BUFFER_SIZE		= "BUFFER_SIZE";
	static final String SIGNING		= "SIGNING";
	static final String ENCRYPTION		= "ENCRYPTION";

	static Connection connection;
	static SMBClient client;
	static Session session;
	static Map<String, String> opts;

	SMBTEST(String[] args)
	{
		opts = new HashMap<>();

		for (String arg : args) {
			if (arg.contains("=")) {
				String k = arg.substring(0, arg.indexOf('='));
				String v = arg.substring(arg.indexOf('=') + 1);

				System.out.printf("Processing %s = %s\n",
						  k, v);
				opts.put(k, v);
			}
		}
	}

	private int __init_smb2_config()
	{
		try {
			this.client = new SMBClient();

			System.out.println("Init SMB2");
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	private int __init_smb302_config()
	{
		try {
			boolean sign = false;
			boolean encrypt = false;

			if (opts.containsKey(SIGNING) && opts.get(SIGNING).equals("yes"))
				sign = true;
			if (opts.containsKey(ENCRYPTION) && opts.get(ENCRYPTION).equals("yes")) {
				encrypt = true;
				sign = false;
			}

			if (encrypt) {
				EnumSet<SMB2GlobalCapability> set = EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU);

				set.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DFS);
				set.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION);
			}

			SmbConfig config = SmbConfig.builder()
					.withDialects(SMB2Dialect.SMB_3_0_2)
					.withSecurityProvider(new BCSecurityProvider())
					.withEncryptData(encrypt)
					.withDfsEnabled(encrypt)
					.withSigningRequired(sign)
					.build();

			this.client = new SMBClient(config);
			System.out.println("Init SMB3.02");
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	private int __init_smb311_config()
	{
		try {
			boolean sign = false;
			boolean encrypt = false;

			if (opts.containsKey(SIGNING) && opts.get(SIGNING).equals("yes"))
				sign = true;
			if (opts.containsKey(ENCRYPTION) && opts.get(ENCRYPTION).equals("yes")) {
				encrypt = true;
				sign = false;
			}

			if (encrypt) {
				Provider[] providerList = java.security.Security.getProviders();
				BouncyCastleProvider bcSecurityProvider = new BouncyCastleProvider();
				java.security.Security.insertProviderAt(bcSecurityProvider, providerList.length);
				EnumSet<SMB2GlobalCapability> set = EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU);

				set.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DFS);
				set.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION);
			}

			SmbConfig config = SmbConfig.builder()
				.withDialects(SMB2Dialect.SMB_3_1_1)
				.withDfsEnabled(encrypt)
				.withEncryptData(encrypt)
				.withSigningRequired(sign)
				.build();

			this.client = new SMBClient(config);
			System.out.println("Init SMB3.11");
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	public int init_connection()
	{
		if (opts.get(SMB_VERS).equals("2"))
			return __init_smb2_config();
		if (opts.get(SMB_VERS).equals("3.02"))
			return __init_smb302_config();
		if (opts.get(SMB_VERS).equals("3.11"))
			return __init_smb311_config();

		System.out.println("Unsupported SMB_VERS");
		return -1;
	}

	public int login()
	{
		try {
			this.connection = client.connect(opts.get(SERVER));
			AuthenticationContext ac = new AuthenticationContext(opts.get(USER_NAME),
									     opts.get(PASSWORD).toCharArray(),
									     opts.get(DOMAIN));
			this.session = connection.authenticate(ac);
			System.out.println("Session created");

			if (this.connection.isClientDecidedEncrypt())
				System.out.println("Client Decide Encrypt: YES");
			else
				System.out.println("Client Decide Encrypt: NO");

			if (connection.getNegotiatedProtocol().getDialect().isSmb3x())
				System.out.println("Session type: SMB3");
			else
				System.out.println("Session: NOT SMB3");

			if (connection.getConnectionInfo().isConnectionSupportEncrypt())
				System.out.println("Session Encryption: supported");
			else
				System.out.println("Session Encryption: NOT supported");

			if (session.isSigningRequired())
				System.out.println("Session Signing: required");
			else
				System.out.println("Session Signing: NOT required");

			if (session.isGuest())
				System.out.println("Session Guest: yes");
			else
				System.out.println("Session Guest: no");

			if (session.isAnonymous())
				System.out.println("Session Anonymous: yes");
			else
				System.out.println("Session Anonymous: no");

		} catch (IOException e) {
			e.printStackTrace();
			return -1;
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	public int logoff()
	{
		try {
			this.session.logoff();
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	public int read_test()
	{
		try {
			if (!opts.containsKey(REMOTE_RFILE)) {
				System.out.println("Skip read_test()");
				return 0;
			}

			DiskShare share = (DiskShare) session.connectShare(opts.get(SHARE_NAME));
			HashSet<SMB2ShareAccess> s = new HashSet<SMB2ShareAccess>();

			System.out.printf("READ: Remote file //%s/%s/%s\n",
					opts.get(SERVER),
					opts.get(SHARE_NAME),
					opts.get(REMOTE_RFILE));

			s.add(SMB2ShareAccess.ALL.iterator().next());

			com.hierynomus.smbj.share.File remote =
					share.openFile(opts.get(REMOTE_RFILE),
							EnumSet.of(AccessMask.GENERIC_READ),
							null,
							SMB2ShareAccess.ALL,
							SMB2CreateDisposition.FILE_OPEN,
							null);

			System.out.printf("Local file %s\n", opts.get(LOCAL_RWFILE));

			java.io.File local = new java.io.File(opts.get(LOCAL_RWFILE));
			InputStream is = remote.getInputStream();
			FileOutputStream os = new FileOutputStream(local);

			int length = Integer.parseInt(opts.get(BUFFER_SIZE));
			byte[] buffer = new byte[length];

			long total_bytes = 0;
			Duration total_est = Duration.ZERO;

			while (true) {
				Instant st = Instant.now();
				length = is.read(buffer);
				if (length <= 0)
					break;
				Instant en = Instant.now();
				total_est = total_est.plus(Duration.between(st, en));
				total_bytes += length;

				os.write(buffer, 0, length);
			}

			is.close();
			os.close();

			System.out.println("read_test(): " + total_bytes +
					   " bytes, elapsed " + total_est);
			System.out.println("read_test() done");
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	public int write_test()
	{
		try {
			if (!opts.containsKey(REMOTE_WFILE)) {
				System.out.println("Skip write_test()");
				return 0;
			}

			DiskShare share = (DiskShare) session.connectShare(opts.get(SHARE_NAME));
			HashSet<SMB2ShareAccess> s = new HashSet<SMB2ShareAccess>();

			System.out.printf("WRITE: Remote file //%s/%s/%s\n",
					opts.get(SERVER),
					opts.get(SHARE_NAME),
					opts.get(REMOTE_WFILE));

			s.add(SMB2ShareAccess.ALL.iterator().next());

			com.hierynomus.smbj.share.File remote =
					share.openFile(opts.get(REMOTE_WFILE),
							EnumSet.of(AccessMask.GENERIC_WRITE),
							EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
							EnumSet.of(SMB2ShareAccess.FILE_SHARE_WRITE),
							SMB2CreateDisposition.FILE_OVERWRITE_IF,
							null);

			System.out.printf("Local file %s\n", opts.get(LOCAL_RWFILE));

			InputStream local = new java.io.FileInputStream(opts.get(LOCAL_RWFILE));
			int length = Integer.parseInt(opts.get(BUFFER_SIZE));
			byte[] buffer = new byte[length];
			long total_bytes = 0;
			int offt = 0;
			Duration total_est = Duration.ZERO;
			int avail = local.available();

			while (avail > 0) {
				length = local.read(buffer);
				if (length <= 0)
					break;

				if (avail < length) {
					length = avail;
					avail = 0;
				}

				avail -= length;
				total_bytes += length;
				Instant st = Instant.now();
				offt += remote.write(buffer, offt, 0, length);
				Instant en = Instant.now();
				total_est = total_est.plus(Duration.between(st, en));
			}

			System.out.println("write_test(): " + total_bytes +
					   " bytes, elapsed " + total_est);

			remote.flush();
			remote.close();
			local.close();

			System.out.println("write_test() done");
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}
}

public class App
{
	public static void main(String[] args)
	{
		SMBTEST st = new SMBTEST(args);

		if (st.init_connection() != 0)
			return;
		if (st.login() != 0)
			return;

		if (st.read_test() == 0)
			st.write_test();

		st.logoff();
	}
}
