package ab1.impl.Nachnamen;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

import ab1.RSA;

public class RSAImpl implements RSA {
	private BigInteger lastPrime = BigInteger.ZERO;
	private static int zeroFill =10;

	@Override
	public BigInteger generatePrime(int n) {
		//Nutze Biginteger.probablePrime, n Bitlänge
		Random rnd = new Random();
		BigInteger prime;
		prime = BigInteger.probablePrime(n,rnd);
		
		while(prime.equals(lastPrime)){
			rnd = new Random();
			prime = BigInteger.probablePrime(n,rnd);	
		}
		lastPrime= prime;
			return prime;
	}

	@Override
	public BigInteger generateEncryptionExponent(BigInteger p, BigInteger q) {
		BigInteger n = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));
		//Miller Rabins Test 
		BigInteger e = new BigInteger("3");
		while(e.gcd(n).compareTo(BigInteger.ONE)!=0){
			e= e.add(new BigInteger("2"));
		}
		return e;
	}

	@Override
	public BigInteger generateDecryptionExponent(BigInteger e, BigInteger q, BigInteger p) {
		
		BigInteger n = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));
		BigInteger temp_n = n;
		
		//e*d mod (n) = 1
		BigInteger d;
		BigInteger rest = new BigInteger("-1");
		BigInteger result = BigInteger.ZERO;
		BigInteger  t  = BigInteger.ZERO;
		BigInteger  u  = BigInteger.ZERO;
		BigInteger u_new = BigInteger.ZERO;
		BigInteger  v_new = BigInteger.ZERO;
		BigInteger s = BigInteger.ONE;
		BigInteger  v = BigInteger.ONE;
		
		while (!rest.equals(BigInteger.ZERO)){
		//System.out.println("Rest" +rest);
		result = e.divide(n);
		u_new = s.subtract((result.multiply(u)));
		v_new = t.subtract((result.multiply(v)));
		s = u;
		t = v;
		u =u_new;
		v =v_new;
		rest = e.mod(n);
		e = n;
		n= rest;
		//rest = p.mod(q);
		//p = q;
		//q= rest;
		}
		d = t.multiply(u);
		 if(d.compareTo(BigInteger.ZERO)<0)
		return(d.add(temp_n));	 
		 else 
		return d;
	}

	@Override
	public byte[] encrypt(byte[] message, BigInteger n, BigInteger e) {
		//C = M e mod n
		//ArrayList <Byte> tempArray = new ArrayList<Byte>();
		byte[] c =null;
		//int zeroBuffer;
		byte[]result = new byte[zeroFill];
		
		for (int i = 0; i<message.length;i++){
			BigInteger bigIntegerMessage = BigInteger.valueOf(message[i]);	
			BigInteger encryptedMessage =bigIntegerMessage.modPow(e, n);
			c= encryptedMessage.toByteArray();
		}
		
		for (int i = 0, j = 0; i<zeroFill && j <c.length;i++){
			if(i<c.length){
				result[i]=0;
			
			}
			else{
				result[i]=c[j++];
				//j++;
			}
				
		}
		return result;
	}	
		
		
/*      BigInteger bigIntegerMessage = new BigInteger(1,message);
      System.out.println("messagealsbigint"+bigIntegerMessage);
     BigInteger encryptedMessage =bigIntegerMessage.modPow(e, n);
     System.out.println("encrypted"+encryptedMessage);
		return encryptedMessage.toByteArray();*/


	@Override
	public byte[] decrypt(byte[] cipher, BigInteger n, BigInteger d) {
		//M = C^d mod n
		
		byte[]tempResult = new byte[zeroFill];
		ArrayList<Byte> resultCollection = new ArrayList<Byte>();
		int check = zeroFill-1;
		
		for(int i = 0; i< cipher.length;i++){
			tempResult[i% zeroFill]= cipher[i];
		
			if(i == check){
				BigInteger bigIntegerCipher = new BigInteger(cipher);
				BigInteger decryptedMessage =bigIntegerCipher.modPow(d, n);
			resultCollection.add( decryptedMessage.byteValue());
			check+= zeroFill;
			}
		}
		
		byte[] finalResult = new byte[resultCollection.size()];
		for(int i=0; i<resultCollection.size();i++){
			finalResult[i]=resultCollection.get(i);
		}
		
	/*	BigInteger bigIntegerCipher = new BigInteger(cipher);
		BigInteger decryptedMessage =bigIntegerCipher.modPow(d, n);
		c[i]=decryptedMessage.toByteArray();*/
	return finalResult;	
	}




}