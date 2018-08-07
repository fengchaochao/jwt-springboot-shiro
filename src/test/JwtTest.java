import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.shiro.util.Assert;

import java.io.UnsupportedEncodingException;
import java.util.Date;

public class JwtTest {


	// 过期时间5分钟
	private static final long EXPIRE_TIME = 5 * 60 * 1000;

	public static String sign(String username,int age, String secret) {
		try {
			Date date = new Date(System.currentTimeMillis() + EXPIRE_TIME);
			Algorithm algorithm = Algorithm.HMAC256(secret);
			// 附带username信息
			return JWT.create()
					.withClaim("username", username)
					.withClaim("age", age)
					.withExpiresAt(date)
					.sign(algorithm);
		} catch (UnsupportedEncodingException e) {
			return null;
		}
	}

	/**
	 * 校验token是否正确
	 *
	 * @param token  密钥
	 * @param secret 用户的密码
	 * @return 是否正确
	 */
	public static boolean verify(String token, String username, int age,String secret) {
		try {
			Algorithm algorithm = Algorithm.HMAC256(secret);
			JWTVerifier verifier = JWT.require(algorithm)
					.withClaim("username", username)
					.withClaim("age", age)
					.build();
			DecodedJWT jwt = verifier.verify(token);
			return true;
		} catch (Exception exception) {
			return false;
		}
	}

	/**
	 * 获得token中的信息无需secret解密也能获得
	 *
	 * @return token中包含的用户名
	 */
	public static String getUsername(String token) {
		try {
			DecodedJWT jwt = JWT.decode(token);
			return jwt.getClaim("username").asString();
		} catch (JWTDecodeException e) {
			return null;
		}
	}

	public static void main(String[] args) {
		String sign = sign("fengchao", 21, "105115");
		System.out.println(sign);
		DecodedJWT jwt = JWT.decode(sign);
		String username = jwt.getClaim("username").asString();
		String age = jwt.getClaim("age").asString();
		System.out.println(username +"~~~"+ age);

		boolean verify = verify(sign, "fengchao", 28, "105115");
		Assert.isTrue(verify,"YES!!!");

	}
}
