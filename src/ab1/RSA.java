package ab1;

import java.math.BigInteger;


/**
 * Interface für die Verwendung des RSA-Kryptosystems.
 * 
 * @author Raphael Wigoutschnigg
 */
public interface RSA{
	/**
	 * Erzeugt eine Primzahl mit n-Bit Länge
	 * @param n ... Länge der Primzahl
	 * @return Primzahl
	 */
	public BigInteger generatePrime(int n);
	
	/**
	 * Erzeugt mithilfe von p und q den öffentlichen Exponenten e
	 * @param p ... 1. Primzahl des RSA-Verfahrens
	 * @param q ... 2. Primzahl des RSA-Verfahrens
	 * @return öffentlicher Exponent
	 */
	public BigInteger generateEncryptionExponent(BigInteger p, BigInteger q);
	
	/**
	 * Erzeugt aus p, q und e den geheimen Exponenten d
	 * @param p ... 1. Primzahl des RSA-Verfahrens
	 * @param q ... 2. Primzahl des RSA-Verfahrens
	 * @param e ... öffentlicher Schlüssel
	 * @return geheimer Exponent
	 */
	public BigInteger generateDecryptionExponent(BigInteger p, BigInteger q, BigInteger e);
	
	/**
	 * Verschlüsselt eine Nachricht
	 * @param message ... zu verschlüsselnde Nachricht
	 * @param n ... Modulus
	 * @param e ... öffentlicher Exponent
	 * @return
	 */
	public byte[] encrypt(byte[] message, BigInteger n, BigInteger e);
	
	/**
	 * Entschlüsselt eine Nachricht
	 * @param cipher ... Chiffrat
	 * @param n ... Modulus
	 * @param d ... geheimer Exponent
	 * @return Entschlüsselte Daten
	 */
	public byte[] decrypt(byte[] cipher, BigInteger n, BigInteger d);
}
