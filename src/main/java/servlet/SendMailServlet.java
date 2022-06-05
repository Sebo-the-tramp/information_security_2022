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
			byte[] t = Generics.fromHex(key_hex);
			
			Key publicKey = 
				    KeyFactory.getInstance("RSA").generatePublic((KeySpec) new X509EncodedKeySpec(t));
			return publicKey;
		}else {
			throw new InvalidKeySpecException();
		}				
		
	}
	
}
