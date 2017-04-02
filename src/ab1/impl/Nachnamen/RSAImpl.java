package ab1.impl.Nachnamen;

import ab1.RSA;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

public class RSAImpl implements RSA {
	private BigInteger lastPrime = BigInteger.ZERO;

	@Override
	public BigInteger generatePrime(int n) {
		// Nutze Biginteger.probablePrime, n Bitlänge
		Random rnd = new Random();
		BigInteger prime;
		prime = BigInteger.probablePrime(n, rnd);

		while (prime.equals(lastPrime)) {
			rnd = new Random();
			prime = BigInteger.probablePrime(n, rnd);
		}
		lastPrime = prime;
		return prime;
	}

	@Override
	public BigInteger generateEncryptionExponent(BigInteger p, BigInteger q) {
		// n muss kleiner als p*q sein
		// e muss teilerfremd sein
		// (p*q) und e sind öffentlicher Schlüssel
		BigInteger n = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));
		BigInteger e = new BigInteger("3");
		while (e.gcd(n).compareTo(BigInteger.ONE) != 0) {
			e = e.add(new BigInteger("2"));
		}
		return e;
	}

	@Override
	public BigInteger generateDecryptionExponent(BigInteger p, BigInteger q, BigInteger e) {
		// d und (q*p) & d sind privater Schlüssel
		// Es gilt (e * d) mod ((p-1)*(q-1)) = 1
		BigInteger n = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		// BigInteger n = p.multiply(q);
		BigInteger temp_n = n;

		// Erweiterter euklidischer Algorithmus Tabelle
		BigInteger d;
		BigInteger rest = new BigInteger("-1");
		BigInteger quotient = BigInteger.ZERO;
		BigInteger t = BigInteger.ZERO;
		BigInteger u = BigInteger.ZERO;
		BigInteger u_new = BigInteger.ZERO;
		BigInteger v_new = BigInteger.ZERO;
		BigInteger s = BigInteger.ONE;
		BigInteger v = BigInteger.ONE;

		while (!rest.equals(BigInteger.ZERO)) {
		
			quotient = n.divide(e);
			u_new = s.subtract((quotient.multiply(u)));
			v_new = t.subtract((quotient.multiply(v)));
			s = u;
			t = v;
			u = u_new;
			v = v_new;
			rest = n.mod(e);
			n = e;
			e = rest;
		}
		d = t;

		// Falls d negativ, addiere n
		if (d.compareTo(BigInteger.ZERO) < 0) {
			//System.out.println("d=" + d.add(temp_n));
			return (d.add(temp_n));
		} else
			//System.out.println("d=" + d);
		return d;

	
	}

	@Override
	public byte[] encrypt(byte[] message, BigInteger n, BigInteger e) {
		// Zerlege Nachricht in Blöcke: Bitlänge(Block) <= Bitlänge(n)-1
		int blockSize = (n).bitLength()-1;
		ArrayList<Byte> resultCollection = new ArrayList<Byte>();
		int zeroBuffer;
		Byte zero = 0;
		byte[] tempArray;

		for (int i = 0; i < message.length; i++) {
			BigInteger bigIntegerMessage = BigInteger.valueOf(message[i]);
			BigInteger encryptedMessage = bigIntegerMessage.modPow(e, n);
			tempArray = encryptedMessage.toByteArray();
			zeroBuffer = blockSize - tempArray.length;

			while (zeroBuffer > 0) {
				resultCollection.add(zero);
				zeroBuffer--;

			}
			for (int j = 0; j < tempArray.length; j++) {
				resultCollection.add(tempArray[j]);
			}

			// c= encryptedMessage.toByteArray();
			// resultCollection.add(c[i]); }
		}
		byte[] result = new byte[resultCollection.size()];
		for (int i = 0; i < resultCollection.size(); i++) {
			result[i] = (resultCollection.get(i));
		}

		return result;
	}

	@Override
	public byte[] decrypt(byte[] cipher, BigInteger n, BigInteger d) {
		// M = C^d mod n
	
		int blockSize = (n).bitLength()-1;
	
		byte[] tempResult = new byte[blockSize];
		ArrayList<Byte> resultCollection = new ArrayList<Byte>();
		int check = blockSize - 1;

		for (int i = 0; i < cipher.length; i++) {
			tempResult[i % blockSize] = cipher[i];
	
			if (i == check) {
				BigInteger bigIntegerCipher = new BigInteger(tempResult);
				BigInteger decryptedMessage = bigIntegerCipher.modPow(d, n);
				resultCollection.add(decryptedMessage.byteValue());
				check += blockSize;

			}
		}

		byte[] result = new byte[resultCollection.size()];
		for (int i = 0; i < resultCollection.size(); i++) {
			result[i] = resultCollection.get(i);
		}

		return result;
	}
}