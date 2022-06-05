package servlet;

import jakarta.servlet.http.HttpServlet;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.Properties;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import utils.Generics;
import utils.RSAEncryptDecrypt;

/**
 * Servlet implementation class SendMailServlet
 */
@WebServlet("/SendMailServlet")
public class SendMailServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private static final String USER = "root";
	private static final String PWD = "MyN3wP4ssw0rd";
	private static final String DRIVER_CLASS = "org.mariadb.jdbc.Driver";
	private static final String DB_URL = "jdbc:mariadb://localhost:3306/examDB?encrypt=true;trustServerCertificate=true;";
	
	private static final String key_hex = "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100cc6a3840783465248b21ef25c3fa6edcbcc867e0d4a903c64b88e20c1c42ea3237ef540fb2e2079572d2046545e96b519787b468bcf9c312a8082804a93f428b1525609e7e51bb1265048dbc941770989e0dc18e1569ad0c101470b010769ee66a92b8432f0817f9250ed9ae0e01dda4a3027721ad7837e12d85f2d235c40599233482bb23dafc7cc339efc7b04751b36849c26191dc20ab1f89e0474393582a64865a352b032c2fa0688cda85398cf3cf7c236b0c1a1056a0b9d17f9fdeb9b4dfb146189575898949736ba01b1a7a77b2f41eaffe73e31e3ab70a730b1135bb38ceb835a4318c31dcbda8f61c33110e0ff78591e8899ec80e7cec197a8abf21020301000102820101009af178aa057351a71d7f1f52b4f642ca369e817ebe334e9523f421c3a4386464a45958927db92e9e6d661bc6d7f352518a5666bd6d60b428940d7aa7edd1f19292f8bdffe527f670bef970a61c6a980256eb7e67407bd59b6b24d335e184c875471ae768a561b12a3c98c10f59b6b8566ee9137c078d346e0e9f95ab18edf87efc8b4397752b2a512c9ef105b075050d8c2d6ba35571691a4d04ca3df7da4d53d6dd4510c013f73f45e64ad2d1eef7a02aca378b10f6b42eacb444cfced79baade26b29366064724f649310dd6dbefe9872ac39a9d209b99dc571405c2a4405a8c12906cf70c6269acba0f755ab90801d06ff73201db1b0e4e71708e2274000102818100e75a327a2f390b3cd15cf9361ce839d874a9c10b8aa5768bcaf41f983d60b696b689ff4277416fcf83a3299e11904e00db9c65febb97393714cc5493762e5b51c65305a48be6a87587d13d87876aa2156da7b262932b517e95f70f0365a729d72dc0bc03bf85723c8cb8441e2092ad410aaeea6bc2ef25ac1a774ec57c165e0102818100e23157e328efb30e8f643891f0683ce27822685bdb3320624b011caaf9209bdb1acc92c7a2700c373ad14c6e89f4aefcffe6681e15574c6d907d1d95966db64a8f3fc7fa0b089df15307d439ce727198d6ee936636a3f1f02915915ffc996bef85d2c7c6e958379c4ebe90916e98c4f5667cf220cd743aee6e4301c7be8aa1210281800140d0d32e9c4d7e47d80c1589f48c13ab161c5096b0acc2b717b97016ad06702c8ef4ce045d5b60b162d9dfdc527ec9ac66dd7a92c38ff0c7710fe83894a9b3f8b20c6ec6bf3a1c60def6495ca76c37577fb80ca6a56e6c941d617c703986957ecef375c5bcd05099a689dfebe73f7f01b2cedc44930d0e309a82d7b9035a0102818100b0a5f48b55770d91bb6e7bb78dd6fa65ab88c393a936de7da531f31f9b7c59fbdd8c12bd92208b89be87a277598a1bf73e2ac4f9699549fcef30a72021e100d26dd953e5f523ffa56e40d8ff64398079eab15bb021d01bac818974855012c976c03e8302d74dabf08896cef4a538ede8f0e7777922bb3922e83db0703c60abc10281805d1d9b220177ef09d0bbf46e196553d0c85665bf9c50dfb6654420c40919a4b8f089691eaa2e49a9f9c64cb3685c51ecbb8eae86fb4e4b2743634f31eba528a1aa4ee738f8182e7128a8927f6721baf3e46dae9e2ec1bb0ca8d6693ad13172a0ccd9d21e2709161041f4be044cb6a28f0fb7e368bb450fd5a5fb3affb2bb97e8";
	private static final String key_hex_dav = "308204bc020100300d06092a864886f70d0101010500048204a6308204a2020100028201010087cb4d87c21b067bd16a5bc28ba62afc4de209f4c5fc828e8640078ad3d1d1808b1f860a61eb350c208d84d1779cb52d89659595e57e2e7e35cc8019ea2f317cd26f82ebed12827e9833386e50061603ed6ccaf3954f3dde7cb39870d8f0d58fdd0da99e0be5e465fbedca43e243b340b4d4ade55f530008b53fd5fb356bc8c980e5fdc8155f7fdcb36f7b0d6b35fbe149d43e5432db4b6acec425cef2c10455377709eb3ab5295c9e7252882ba43a7ba795679a79c67893ea5d021bb32c263cd0001f5041b21d34fad34df2823aaf73302035f96a9471073eb7829a38e17058fc4d05f18ebe67edcdb09efcc2cd95538c9e07bc26aa72b9f7507bf33187945b02030100010282010077e18a5b9c88014c540f625cb8ae84ea62d377d8a8e508594cb9c02ed65b386a13e84b8c64efa1d047f8c7d5a89426fac17e75f57439d64fc3acfb3665a12e3e35050efebb37890ebbcd143786dc289965049393413048bd5f37aa0f8de5e793ef21fda93275cd121fbbc8c1ef41b7411ba35ab5d156d403dc0734206703f5a86b7bac6961ddfc8ec6b2f466cf5f080ba0ff96dee5e0647f8a1c2e241750bb0de7921cd63e990b6512191e00e6330b4cb53931c1220f638b8e61a3631bfacb5fca4cf3f2121eb33b735743d04d6b31604f806b0e92a2b6aeffbb940c27a393fc5adc8126fcb672c13c24ce1c9c499992b91c4eec9e89c9ae0e06d6a0584859d902818100d1793c538585ec9efa55d1f28b815e56421874472a6abc8faa664d545268c1058724426e1d7e7bb20ae69b534db00da9c9933d22816eac84ad874a2c1899b6b833b41aa483fd9e1de135bfe52dc1096c209491a9e96c3a80f2487ce6c136691d07c69c5ca33d245c603f756dd650f2c941a7f68495447b21e3ba08a45c49fd4f02818100a5f49efdb692c184046464b219104b1ba35cd5f26010b0d689a513ea329740592d4ecef947374c41881ff15692d052ed2a525d1cc173c47425d111b49704f7ac1fe383b8beb4c063aac0599de918258efcf56060ce7492b5ca9e849b6bab6246f4a649b55a85f175d4c237a2c7b2ee5a042b9578c38f32113319d489190ced3502818067c6bc50549228cc0a118255bb2f78611b95a9e5a7ea0148db8e9b38ef2ade95b2821037257d882288abfebfa2795a0b87c5de3fbe07ea8840c009cb16d4f06509986caa9c8985502046d4aee1a004df00b51a0527936ad87f2fd2512fdf98ebbcf2747ca092a5f4edea026f4c0206861674f3f8734ade05c8205e2faf592899028180504a305db965f92000ebfd57b90e8bf7fc2a5f0c1b7417ca43dfcce9c2be3090b47deb5ee91894d9239da8aa64ef4b1f99192e194a72d2fa0a8dc2ce273e6d012690715b0150fbbf7c8e010d880779ac5b2ff00805fa9a3c3fa23fafde0095d4946a9b4095623636f6cf5c1172225c74ca8db78c2cb8ebd52c6ef3c7bc89e77d0281803edc578ba9c1f04487e1fdfd342b9728ba7b8b28cfeee590c6e7a8be42668b064a98ab86635c6ef092c70b64616df2b5e376711a0e9feaad4f552bec701f51fd0d1a78a7bcfd881bf8f7e82e7195995e610189348d0f032fe300ff1ffec4231f41c5f8083c9c781548230b2c22ec2c0a4f5da90a2116e91c957bf4ee062b3c73";
	
    
	private static Connection conn;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public SendMailServlet() {
        super();
        // TODO Auto-generated constructor stub
    }
    
    public void init() throws ServletException {
    	try {
			Class.forName(DRIVER_CLASS);
			
		    Properties connectionProps = new Properties();
		    connectionProps.put("user", USER);
		    connectionProps.put("password", PWD);
	
	        conn = DriverManager.getConnection(DB_URL, connectionProps);
		    
		    //System.out.println("User \"" + USER + "\" connected to database.");
    	
    	} catch (ClassNotFoundException | SQLException e) {
			e.printStackTrace();
		}
    }

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		
		String sender = request.getParameter("email").replace("'", "''");;
		String receiver = request.getParameter("receiver").replace("'", "''");;
		String token = request.getParameter("token").replace("'", "''");;
		String subject = request.getParameter("subject").replace("'", "''").replace("<", "~").replace(">", "~");;
		String body = request.getParameter("body").replace("<", "~").replace(">", "~");;
		String sign = request.getParameter("digital");
		
		System.out.println("signing: " + sign);
		
		long timestamp = new Date(System.currentTimeMillis()).getTime()/1000;
				
		if(!tokenIsValid(token, sender)) {			
			return;		
		}
		
		try {
			Key publicKey = getPublicKeyReceiver(receiver);	
			
			byte[] encrypted = RSAEncryptDecrypt.encrypt(body, publicKey);
			
			String signMail = null;
			
			if(sign != null) {				
				signMail = getSignedEmail(body, sender);
				System.out.println(signMail);
			}
			
			try (Statement st1 = conn.createStatement()) {						
				st1.execute(
					"INSERT INTO mail ( sender, receiver, subject, body, t, signature ) "
					+ "VALUES ( '" + sender + "', '" + receiver + "', '" + subject + "', '" + Generics.toHex(encrypted) + "',FROM_UNIXTIME(" + timestamp + "), '" + signMail + "')"
				);						
										
			} catch (SQLException e) {
				e.printStackTrace();
			}
			
		}catch(Exception e) {
			e.printStackTrace();
		}
		
		request.setAttribute("email", sender);
		request.getRequestDispatcher("home.jsp").forward(request, response);
	}
	
	private String getSignedEmail(String body, String email) throws Exception {	
		
		String filePath = "/home/gerard/Downloads/private_key_" +  email + ".txt";
		System.out.println(filePath);
		
		String res = Generics.readFromFile(filePath);
		res = res.replace("PRIVATE KEY: ", "");;			
		
		byte[] key_byte = Generics.fromHex(res);
		
		KeyFactory kf = KeyFactory.getInstance("RSA");
		
		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(key_byte);
        PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);
		
		return RSAEncryptDecrypt.sign(body, privateKey);		
		
	}
	
	private boolean tokenIsValid(String token, String sender) {
		
		String sql = "SELECT * FROM tokens WHERE token = ?";
		
		try(PreparedStatement st = conn.prepareStatement(sql, ResultSet.TYPE_SCROLL_SENSITIVE, ResultSet.CONCUR_UPDATABLE)){
			
			st.setString(1, token);
			
			ResultSet sqlRes = st.executeQuery();	
			
			if(sqlRes.next() == true) {									
				
				String email = sqlRes.getString("email");				
				sqlRes.first();
				sqlRes.deleteRow();
				
				if(email.compareTo(sender) == 0) {	
					return true;
				}else {
					return false;
				}							
			}else {
				return false;
			}								
		}
		catch (SQLException e) {
			e.printStackTrace();
			return false;
		}				
	}
	
	private Key getPublicKeyReceiver(String receiver) throws InvalidKeySpecException, NoSuchAlgorithmException, SQLException {
		
		String sql = "SELECT public_key FROM user WHERE email = ?";
		
		PreparedStatement st = conn.prepareStatement(sql);
			
		st.setString(1, receiver);
		
		ResultSet sqlRes = st.executeQuery();	
		
		if(sqlRes.next() == true) {	
			System.out.println("trovata");
		
			String key_hex = sqlRes.getString("public_key");		
			byte[] t = fromHex(key_hex);
			
			Key publicKey = 
				    KeyFactory.getInstance("RSA").generatePublic((KeySpec) new X509EncodedKeySpec(t));
			return publicKey;
		}else {
			throw new InvalidKeySpecException();
		}				
		
	}
	
	private byte[] fromHex(String word) {
		
		byte[] binary = new byte[word.length()/2];
		for(int i = 0; i < binary.length; i++) {
			binary[i] = (byte) Integer.parseInt(word.substring(2*i, 2*i +2), 16);
		}
		return binary;
	}
}
