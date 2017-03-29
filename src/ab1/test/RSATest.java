package ab1.test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import org.junit.Assert;
import org.junit.Test;

import ab1.RSA;
import ab1.impl.Nachnamen.RSAImpl;

public class RSATest {
	RSA tools = new RSAImpl();

	private static int KEYLENGTH = 1024;
	private static int TESTCOUNT = 20;
	
	//3 Pts
	@Test
	public void testEncryption() {
		
		byte[] message = "Das ist ein SysSec-Test".getBytes();
		
		BigInteger p = tools.generatePrime(KEYLENGTH);
		BigInteger q = tools.generatePrime(KEYLENGTH);
		
		BigInteger e = tools.generateEncryptionExponent(p, q);
		
		BigInteger d = tools.generateDecryptionExponent(p, q, e);
		
		BigInteger n = p.multiply(q);
		
		byte[] cipher = tools.encrypt(message, n, e);
		
		byte[] message_decrypted = tools.decrypt(cipher, n, d);
		
		Assert.assertArrayEquals(message, message_decrypted);
	}
	
	//3 Pts
	@Test
	public void testEncryption2() {
		
		Random r = new Random(System.currentTimeMillis());
		
		int keyLength = r.nextInt(100)+KEYLENGTH;
		
		BigInteger p = tools.generatePrime(keyLength);
		BigInteger q = tools.generatePrime(keyLength);
		
		BigInteger e = tools.generateEncryptionExponent(p, q);
		
		BigInteger d = tools.generateDecryptionExponent(p, q, e);
		
		BigInteger n = p.multiply(q);
		
		int count = 0;
		for(int i = 0; i < TESTCOUNT; i++)
		{
			System.out.println("Versuch: " + (i+1));
			
					
			byte[] message = new byte[r.nextInt(10000) + 10000];
			
			r.nextBytes(message);

			if(testRSA(tools, message,n,e,d))
				count ++;
		}
		
		Assert.assertEquals(TESTCOUNT, count);
	}
	
	//3 Pts
	@Test
	public void testExponent()
	{
		Random r = new Random(System.currentTimeMillis());
		
		byte[] message = new byte[r.nextInt(10000) + 10000];
		
		r.nextBytes(message);
		
		int keyLength = r.nextInt(100)+KEYLENGTH;
		
		BigInteger p = tools.generatePrime(keyLength);
		BigInteger q = tools.generatePrime(keyLength);
		
		BigInteger e = tools.generateEncryptionExponent(p, q);
		
		BigInteger d = tools.generateDecryptionExponent(p, q, e);
		
		BigInteger phi = p.min(BigInteger.ONE).multiply(q.min(BigInteger.ONE));
		
		Assert.assertEquals(true, phi.gcd(e).equals(BigInteger.ONE));
		Assert.assertEquals(true, phi.gcd(d).equals(BigInteger.ONE));
	}
	
	//3 Pts
	@Test
	public void testParameterLength()
	{
		Random r = new Random(System.currentTimeMillis());
		
		byte[] message = new byte[r.nextInt(10000) + 10000];
		
		r.nextBytes(message);
		
		int keyLength = r.nextInt(3)+KEYLENGTH;
		
		BigInteger p = tools.generatePrime(keyLength);
		BigInteger q = tools.generatePrime(keyLength);
		
		Assert.assertEquals(keyLength, p.bitLength());
		Assert.assertEquals(keyLength, p.bitLength());
	}
	
	
	private static boolean testRSA(RSA tools, byte[] message, BigInteger n, BigInteger e, BigInteger d)
	{
		
		byte[] cipher = tools.encrypt(message, n, e);
		
		byte[] message_decrypted = tools.decrypt(cipher, n, d);
		
		return Arrays.equals(message, message_decrypted);
	}
}
