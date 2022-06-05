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
	
	private static final String key_hex = "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100cc6a3840783465248b21ef25c3fa6edcbcc867e0d4a903c64b88e20c1c42ea3237ef540fb2e2079572d2046545e96b519787b468bcf9c312a8082804a93f428b1525609e7e51bb1265048dbc941770989e0dc18e1569ad0c101470b010769ee66a92b8432f0817f9250ed9ae0e01dda4a3027721ad7837e12d85f2d235c40599233482bb23dafc7cc339efc7b04751b36849c26191dc20ab1f89e0474393582a64865a352b032c2fa0688cda85398cf3cf7c236b0c1a1056a0b9d17f9fdeb9b4dfb146189575898949736ba01b1a7a77b2f41eaffe73e31e3ab70a730b1135bb38ceb835a4318c31dcbda8f61c33110e0ff78591e8899ec80e7cec197a8abf21020301000102820101009af178aa057351a71d7f1f52b4f642ca369e817ebe334e9523f421c3a4386464a45958927db92e9e6d661bc6d7f352518a5666bd6d60b428940d7aa7edd1f19292f8bdffe527f670bef970a61c6a980256eb7e67407bd59b6b24d335e184c875471ae768a561b12a3c98c10f59b6b8566ee9137c078d346e0e9f95ab18edf87efc8b4397752b2a512c9ef105b075050d8c2d6ba35571691a4d04ca3df7da4d53d6dd4510c013f73f45e64ad2d1eef7a02aca378b10f6b42eacb444cfced79baade26b29366064724f649310dd6dbefe9872ac39a9d209b99dc571405c2a4405a8c12906cf70c6269acba0f755ab90801d06ff73201db1b0e4e71708e2274000102818100e75a327a2f390b3cd15cf9361ce839d874a9c10b8aa5768bcaf41f983d60b696b689ff4277416fcf83a3299e11904e00db9c65febb97393714cc5493762e5b51c65305a48be6a87587d13d87876aa2156da7b262932b517e95f70f0365a729d72dc0bc03bf85723c8cb8441e2092ad410aaeea6bc2ef25ac1a774ec57c165e0102818100e23157e328efb30e8f643891f0683ce27822685bdb3320624b011caaf9209bdb1acc92c7a2700c373ad14c6e89f4aefcffe6681e15574c6d907d1d95966db64a8f3fc7fa0b089df15307d439ce727198d6ee936636a3f1f02915915ffc996bef85d2c7c6e958379c4ebe90916e98c4f5667cf220cd743aee6e4301c7be8aa1210281800140d0d32e9c4d7e47d80c1589f48c13ab161c5096b0acc2b717b97016ad06702c8ef4ce045d5b60b162d9dfdc527ec9ac66dd7a92c38ff0c7710fe83894a9b3f8b20c6ec6bf3a1c60def6495ca76c37577fb80ca6a56e6c941d617c703986957ecef375c5bcd05099a689dfebe73f7f01b2cedc44930d0e309a82d7b9035a0102818100b0a5f48b55770d91bb6e7bb78dd6fa65ab88c393a936de7da531f31f9b7c59fbdd8c12bd92208b89be87a277598a1bf73e2ac4f9699549fcef30a72021e100d26dd953e5f523ffa56e40d8ff64398079eab15bb021d01bac818974855012c976c03e8302d74dabf08896cef4a538ede8f0e7777922bb3922e83db0703c60abc10281805d1d9b220177ef09d0bbf46e196553d0c85665bf9c50dfb6654420c40919a4b8f089691eaa2e49a9f9c64cb3685c51ecbb8eae86fb4e4b2743634f31eba528a1aa4ee738f8182e7128a8927f6721baf3e46dae9e2ec1bb0ca8d6693ad13172a0ccd9d21e2709161041f4be044cb6a28f0fb7e368bb450fd5a5fb3affb2bb97e8";
    
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
