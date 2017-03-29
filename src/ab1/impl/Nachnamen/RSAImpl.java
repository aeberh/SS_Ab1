package ab1.impl.Nachnamen;

import java.math.BigInteger;
import java.util.Random;

import ab1.RSA;

public class RSAImpl implements RSA {

	@Override
	public BigInteger generatePrime(int n) {
		//Nutze Biginteger.probablePrime, n Bitlänge
		Random rnd = new Random();
		BigInteger prime;
		prime = BigInteger.probablePrime(n,rnd);
			return prime;
	}

	@Override
	public BigInteger generateEncryptionExponent(BigInteger p, BigInteger q) {
		
		
		BigInteger n = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));
		return n;
	}

	@Override
	public BigInteger generateDecryptionExponent(BigInteger p, BigInteger q,
			BigInteger e) {
		//e*d mod (n) = 1
		BigInteger d;
		BigInteger rest = new BigInteger("-1");
		BigInteger quotient = new BigInteger("0");
		BigInteger  t  = new BigInteger("0");
		BigInteger  u  = new BigInteger("0");
		BigInteger u_new = new BigInteger("0");
		BigInteger  v_new = new BigInteger("0");
		BigInteger s = new BigInteger("1");
		BigInteger  v = new BigInteger("1");
		
		while (!rest.equals(BigInteger.ZERO)){
		System.out.println("Rest" +rest);
		quotient = p.divide(q);
		u_new = s.subtract((quotient.multiply(u)));
		v_new = t.subtract((quotient.multiply(v)));
		s = u;
		t = v;
		u =u_new;
		v =v_new;
		rest = p.mod(q);
		p = q;
		q= rest;
		}
		d = t.multiply(u);
		return d;
	}

	@Override
	public byte[] encrypt(byte[] message, BigInteger n, BigInteger e) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] decrypt(byte[] cipher, BigInteger n, BigInteger d) {
		// TODO Auto-generated method stub
		return null;
	}




}