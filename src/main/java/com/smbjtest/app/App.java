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
	static String SERVER_ADDRESS;
	static String DOMAIN = "";
	static String USERNAME;
	static String PASSWORD;
	static String SHARE_NAME;
	static String LOCAL_PATH;
	static String REMOTE_RFILE_NAME;
	static String REMOTE_WFILE_NAME;
	static String LOCAL_FILE_NAME;
	static Connection connection;
	static SMBClient client;
	static Session session;

	SMBTEST()
	{
		SERVER_ADDRESS = "xxx.xxx.xxx.xxx";
		String DOMAIN = "";
		USERNAME = "xx";
		PASSWORD = "xx";
		SHARE_NAME = "xx";

		LOCAL_PATH = "/xx/";
		REMOTE_RFILE_NAME = "xx";
		REMOTE_WFILE_NAME = "xx";
		LOCAL_FILE_NAME = "xx";
	}

	public int __init_smb2_config()
	{
		try {
			this.client = new SMBClient();
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	public int __init_smb302_config()
	{
		try {
			EnumSet<SMB2GlobalCapability> set = EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU);

			set.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DFS);
			set.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION);

			SmbConfig config = SmbConfig.builder()
				.withDialects(SMB2Dialect.SMB_3_0_2)
				.withSecurityProvider(new BCSecurityProvider())
				.withEncryptData(true)
				.withDfsEnabled(true)
				.build();

			this.client = new SMBClient(config);
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	public int __init_smb311_config()
	{
		try {
			Provider[] providerList = java.security.Security.getProviders();
			BouncyCastleProvider bcSecurityProvider = new BouncyCastleProvider();
			java.security.Security.insertProviderAt(bcSecurityProvider, providerList.length);
			EnumSet<SMB2GlobalCapability> set = EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU);

			set.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DFS);
			set.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_ENCRYPTION);

			SmbConfig config = SmbConfig.builder()
				.withDialects(SMB2Dialect.SMB_3_1_1)
				.withDfsEnabled(true)
				.withEncryptData(true)
				.build();

			this.client = new SMBClient(config);
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	public int __conn()
	{
		try {
			this.connection = client.connect(SERVER_ADDRESS);
			AuthenticationContext ac = new AuthenticationContext(USERNAME, PASSWORD.toCharArray(), DOMAIN);

			this.session = connection.authenticate(ac);
			System.out.println("Session created");

			if (this.connection.isClientDecidedEncrypt())
				System.out.println("Client Decide Encrypt: YES");
			else
				System.out.println("Client Decide Encrypt: NO");

			if (connection.getNegotiatedProtocol().getDialect().isSmb3x())
				System.out.println("Session: SMB3");
			else
				System.out.println("Session: NOT SMB3");
			if (connection.getConnectionInfo().isConnectionSupportEncrypt())
				System.out.println("Session Encryption: supported");
			else
				System.out.println("Session Encryption: NOT supported");

		} catch (IOException e) {
			e.printStackTrace();
			return -1;
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	public int __read()
	{
		try {
			DiskShare share = (DiskShare) session.connectShare(SHARE_NAME);
			HashSet<SMB2ShareAccess> s = new HashSet<SMB2ShareAccess>();

			System.out.printf("READ: Remote file //%s/%s/%s\n",
					SERVER_ADDRESS,
					SHARE_NAME,
					REMOTE_RFILE_NAME);

			s.add(SMB2ShareAccess.ALL.iterator().next());
			com.hierynomus.smbj.share.File remoteSmbjFile =
				share.openFile(REMOTE_RFILE_NAME,
						EnumSet.of(AccessMask.GENERIC_READ),
						null,
						SMB2ShareAccess.ALL,
						SMB2CreateDisposition.FILE_OPEN,
						null);

			System.out.printf("Local file %s%s\n",
					LOCAL_PATH,
					LOCAL_FILE_NAME);

			java.io.File dest = new
				java.io.File(LOCAL_PATH + LOCAL_FILE_NAME);

			InputStream is = remoteSmbjFile.getInputStream();
			FileOutputStream os = new FileOutputStream(dest);

			byte[] buffer = new byte[1024];
			int length;

			while ((length = is.read(buffer)) > 0) {
				System.out.printf("READ %d bytes\n",
						length);
				os.write(buffer, 0, length);
			}
			os.close();
			is.close();
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	public int __write()
	{
		try {
			DiskShare share = (DiskShare) session.connectShare(SHARE_NAME);
			HashSet<SMB2ShareAccess> s = new HashSet<SMB2ShareAccess>();

			System.out.printf("WRITE: Remote file //%s/%s/%s\n",
					SERVER_ADDRESS,
					SHARE_NAME,
					REMOTE_WFILE_NAME);

			s.add(SMB2ShareAccess.ALL.iterator().next());
			com.hierynomus.smbj.share.File remoteSmbjFile =
				share.openFile(REMOTE_WFILE_NAME,
						EnumSet.of(AccessMask.GENERIC_WRITE),
						EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
						EnumSet.of(SMB2ShareAccess.FILE_SHARE_WRITE),
						SMB2CreateDisposition.FILE_OVERWRITE_IF,
						null);

			System.out.printf("Local file %s%s\n",
					LOCAL_PATH,
					LOCAL_FILE_NAME);

			InputStream is = new java.io.FileInputStream(LOCAL_PATH + LOCAL_FILE_NAME);
			remoteSmbjFile.write(new InputStreamByteChunkProvider(is));
			remoteSmbjFile.flush();
			remoteSmbjFile.close();
			is.close();
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

}

public class App
{
	public static void main( String[] args )
	{
		System.out.println( "Hello World!" );

		SMBTEST st = new SMBTEST();

		if (st.__init_smb311_config() != 0)
			return;
		if (st.__conn() != 0)
			return;
		if (st.__read() != 0)
			return;
		if (st.__write() != 0)
			return;
	}
}
