package servlet;

import jakarta.servlet.http.HttpServlet;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import java.util.Random;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import utils.Generics;
import utils.RSAEncryptDecrypt;

/**
 * Servlet implementation class NavigationServlet
 */
@WebServlet("/NavigationServlet")
public class NavigationServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
    
	private static final String USER = "root";
	private static final String PWD = "MyN3wP4ssw0rd";
	private static final String DRIVER_CLASS = "org.mariadb.jdbc.Driver";
	private static final String DB_URL = "jdbc:mariadb://localhost:3306/examDB?encrypt=true;trustServerCertificate=true;";	
    
	private static Connection conn;
    /**
     * @see HttpServlet#HttpServlet()
     */
    public NavigationServlet() {
        super();
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

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		
		String email = request.getParameter("email").replace("'", "''");;
		String pwd = request.getParameter("password").replace("'", "''");;
		
		if (request.getParameter("newMail") != null)
			request.setAttribute("content", getHtmlForNewMail(email, pwd));
		else if (request.getParameter("inbox") != null)
			try {
				request.setAttribute("content", getHtmlForInbox(email));
			} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		else if (request.getParameter("sent") != null)
			request.setAttribute("content", getHtmlForSent(email, pwd));			
		else if (request.getParameter("search") != null) {
			String search = request.getParameter("search").replace("'", "''");;
			request.setAttribute("content", getHtmlForSearch(email, search));	
		}				
		
		request.setAttribute("email", email);
		request.getRequestDispatcher("home.jsp").forward(request, response);
	}

	private String getHtmlForInbox(String email) throws Exception {
		try (Statement st = conn.createStatement()) {
			ResultSet sqlRes = st.executeQuery(
				"SELECT * FROM mail "
				+ "WHERE receiver='" + email + "'"
				+ "ORDER BY t DESC"
			);					
			
			String filePath = "/home/gerard/Downloads/private_key_" +  email + ".txt";						
			String res = Generics.readFromFile(filePath);
			res = res.replace("PRIVATE KEY: ", "");;
										
			byte[] key_byte = Generics.fromHex(res);
			
			KeyFactory kf = KeyFactory.getInstance("RSA");
			
			PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(key_byte);
	        PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);					
					
	        StringBuilder output = new StringBuilder();
			output.append("<div>\r\n");
	        
			while (sqlRes.next()) {
				
				byte[] encrypted_body = Generics.fromHex(sqlRes.getString(4));								
				byte[] decrypted_body = RSAEncryptDecrypt.decrypt(encrypted_body, privateKey);		
				
				String signatureString = sqlRes.getString("signature");
				System.out.println("sign: " + signatureString);
				
				output.append("<div style=\"white-space: pre-wrap;\"><span style=\"color:grey;\">");
				output.append("FROM:&emsp;" + sqlRes.getString("sender") + "&emsp;&emsp;AT:&emsp;" + sqlRes.getString("receiver"));
				
				if(signatureString.compareTo("null") != 0) {				
					
					System.out.println(sqlRes.getString("sender"));
					
					PublicKey pk_sender = getPublicKeyUser(sqlRes.getString("sender"));
					
					boolean result = RSAEncryptDecrypt.verify(new String(decrypted_body), signatureString, pk_sender);
								
		            System.out.println("res: " + result);
		            
		            output.append(" - VERIFIED SIGNATURE: " + result);
		            
				}else {
					output.append(" - EMAIL NOT SIGNED ");
				}
								
				output.append("</span>");
				output.append("<br><b>" + sqlRes.getString(3) + "</b>\r\n");
				output.append("<br>" + new String(decrypted_body));
				output.append("</div>\r\n");
				
				output.append("<hr style=\"border-top: 2px solid black;\">\r\n");
			}
			
			output.append("</div>");
			
			return output.toString();
			
		} catch (SQLException e) {
			e.printStackTrace();
			return "ERROR IN FETCHING INBOX MAILS!";
		}
	}
	
	private String getHtmlForNewMail(String email, String pwd) {
		
		String generatedString = getRandomString();
		String returnValue = "";
				
		try(Statement st = conn.createStatement()){			
			st.executeQuery("INSERT INTO tokens VALUES('" + generatedString +"','" + email + "')");
			
			System.out.println(generatedString);
			
			returnValue = 
				"<form id=\"submitForm\" class=\"form-resize\" action=\"SendMailServlet\" method=\"post\">\r\n"
				+ "		<input type=\"hidden\" name=\"email\" value=\""+email+"\">\r\n"
				+ "		<input type=\"hidden\" name=\"token\" value=\""+generatedString+"\">\r\n"
				+ "		<input type=\"hidden\" name=\"password\" value=\""+pwd+"\">\r\n"
				+ "		<input class=\"single-row-input\" type=\"email\" name=\"receiver\" placeholder=\"Receiver\" required>\r\n"
				+ "		<input class=\"single-row-input\" type=\"text\"  name=\"subject\" placeholder=\"Subject\" required>\r\n"
				+ "		<textarea class=\"textarea-input\" name=\"body\" placeholder=\"Body\" wrap=\"hard\" required></textarea>\r\n"
				+ "     <input type=\"checkbox\" id=\"digitallysigned\" name=\"digital\" value=\"true\">\n"
				+ "		<label for=\"digital\">Do you want to digitally sign the mail</label><br>"
				+ "		<input type=\"submit\" name=\"sent\" value=\"Send\">\r\n"
				+ "	</form>";
			
		}catch(SQLException e) {
			e.printStackTrace();		
		}
		
		return returnValue;
	   
	}
	
	private String getRandomString() {
		int leftLimit = 48; // numeral '0'
	    int rightLimit = 122; // letter 'z'
	    int targetStringLength = 20;
	    Random random = new Random();
		
		String generatedString = random.ints(leftLimit, rightLimit + 1)
			      .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
			      .limit(targetStringLength)
			      .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
			      .toString();
	
		return generatedString;
	}
	
	private String getHtmlForSent(String email, String pwd) {
		try (Statement st = conn.createStatement()) {
			ResultSet sqlRes = st.executeQuery(
				"SELECT * FROM mail "
				+ "WHERE sender='" + email + "'"
				+ "ORDER BY t DESC"
			);
			
			StringBuilder output = new StringBuilder();
			
			output.append("<div style=\"white-space: pre-wrap;\"><span style=\"color:grey;\">");
			
			output.append("<form id=\"submitForm\" class=\"form-resize\" action=\"NavigationServlet\" method=\"post\">\r\n");
			output.append("<input type=\"hidden\" name=\"email\" value=\""+email+"\">\r\n");
			output.append("<input type=\"hidden\" name=\"password\" value=\""+pwd+"\">\r\n");
			output.append("<input class=\"single-row-input\" name=\"search\" placeholder=\"Search\" required>\r\n");
			output.append("<input type=\"submit\" name=\"search\" value=\"Search\">\r\n");
			output.append("</form>");		
			output.append("</div>\r\n");											
			output.append("<hr style=\"border-top: 2px solid black;\">\r\n");
			
			while (sqlRes.next()) {
				output.append("<div style=\"white-space: pre-wrap;\"><span style=\"color:grey;\">");
				output.append("TO:&emsp;" + sqlRes.getString(2) + "&emsp;&emsp;AT:&emsp;" + sqlRes.getString(5));
				output.append("</span>");
				output.append("<br><b>" + sqlRes.getString(3) + "</b>\r\n");
				output.append("<br>" + sqlRes.getString(4));
				output.append("</div>\r\n");				
				output.append("<hr style=\"border-top: 2px solid black;\">\r\n");
			}
			
			output.append("</div>");
			
			return output.toString();
			
		} catch (SQLException e) {
			e.printStackTrace();
			return "ERROR IN FETCHING INBOX MAILS!";
		}
	}
	
	private String getHtmlForSearch(String email, String param) {
		try (Statement st = conn.createStatement()) {
			ResultSet sqlRes = st.executeQuery(
				"SELECT * FROM mail "
				+ "WHERE sender='" + email + "'"
				+ "ORDER BY t DESC"
			);
			
			StringBuilder output = new StringBuilder();	
			
			if(param.matches("[\\w*\\s*]*")) {
				output.append("<p>Results for search: " + param + "</p>");
			}else {
				output.append("<p>The search key was dangerous, retry!</p>");
			}		
			
			output.append("<div>\r\n");	
			
			while (sqlRes.next()) {
				output.append("<div style=\"white-space: pre-wrap;\"><span style=\"color:grey;\">");
				output.append("TO:&emsp;" + sqlRes.getString(2) + "&emsp;&emsp;AT:&emsp;" + sqlRes.getString(5));
				output.append("</span>");
				output.append("<br><b>" + sqlRes.getString(3) + "</b>\r\n");
				output.append("<br>" + sqlRes.getString(4));
				output.append("</div>\r\n");
				
				output.append("<hr style=\"border-top: 2px solid black;\">\r\n");
			}
			
			output.append("</div>");
			
			return output.toString();
			
		} catch (SQLException e) {
			e.printStackTrace();
			return "ERROR IN SEARCHING INBOX MAILS!";
		}
	}
	
private PublicKey getPublicKeyUser(String email) throws InvalidKeySpecException, NoSuchAlgorithmException, SQLException {
		
		String sql = "SELECT public_key FROM user WHERE email = ?";
		
		PreparedStatement st = conn.prepareStatement(sql);
			
		st.setString(1, email);
		
		ResultSet sqlRes = st.executeQuery();	
		
		if(sqlRes.next() == true) {	
			System.out.println("trovata");
		
			String key_hex = sqlRes.getString("public_key");		
			
			byte[] publicKeyBytes = Generics.fromHex(key_hex);
			
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
			return keyFactory.generatePublic(publicKeySpec);
						
		}else {
			throw new InvalidKeySpecException();
		}				
		
	}
}
