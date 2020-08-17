 package com.westpac.gemini.encryption;
 
 import java.io.ByteArrayOutputStream;
 import java.io.IOException;
 import java.io.ObjectOutputStream;
 import java.io.Serializable;
 import java.math.BigInteger;
 import java.security.MessageDigest;
 import java.security.NoSuchAlgorithmException;
 import java.security.SecureRandom;
 import java.util.Arrays;
 import java.util.HashMap;
 import java.util.Map;
 import java.util.logging.Level;
 import java.util.logging.Logger;
 import org.apache.commons.codec.binary.Base64;

import com.adminserver.utl.StringHelperUtl;
 
 public class EncryptionHelperUtl
 {
   private static final int INDEX_NUMBER_OF_ITERATIONS = 0;
   private static final int INDEX_ALGORITHM_CODE = 4;
   private static final int INDEX_RANDOM_STRING = 6;
   private static final int INDEX_ENCRYPTED_PASSWORD = 14;
   private static final String ALGORITHM_MD5 = "MD5";
   public EncryptionHelperUtl() {}
   
   public static enum Algorithm
   {
	   
     SHA256("01", "SHA-256"),  SHA384("02", "SHA-384"),  SHA512("03", "SHA-512");
	 private static final Map<String, String> lookup;
     static { 
    	 lookup = new HashMap();
       
 
       for (Algorithm s : values()) {
         lookup.put(s.getCode(), s.getName());
       }
     }
     
     private Algorithm(String code, String name)
     {
       this.code = code;
       this.name = name;
     }
     
     public String getCode()
     {
       return this.code;
     }
     
     public String getName()
     {
       return this.name;
     }
     
     public static String getAlgorithmName(String code)
     {
       return (String)lookup.get(code);
     }
     
 
     private final String code;
     
     private final String name;
   }
   
   private static char[] encryptPassword(String userName, char[] encryptedPassword, char[] userEnteredPassword)
     throws NoSuchAlgorithmException
   {
     char[] numberOfIterationsArray = Arrays.copyOfRange(encryptedPassword, 0, 4);
     String numberOfIterations = String.valueOf(numberOfIterationsArray);
     char[] algorithmCodeArray = Arrays.copyOfRange(encryptedPassword, 4, 6);
     String algorithmCode = String.valueOf(algorithmCodeArray);
     char[] randomStringArray = Arrays.copyOfRange(encryptedPassword, 6, 14);
     String randomString = String.valueOf(randomStringArray);
     
     StringBuilder userPassword = doEncryption(userName, userEnteredPassword, numberOfIterations, algorithmCode, randomString);
     return userPassword.toString().toCharArray();
   }
   
   public static String encryptPassword(String userName, char[] userEnteredPassword, String numberOfIterations, String algorithmCode)
   {
     StringBuilder userPassword = new StringBuilder();
     String randomString = "00000000";
     
     try
     {
       SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
       StringBuilder randomNumber = new StringBuilder();
       for (int x = 1; x <= 8; x++) {
         randomNumber = randomNumber.append(new Integer(secureRandom.nextInt(10)).toString());
       }
       randomString = randomNumber.toString();
       userPassword = doEncryption(userName, userEnteredPassword, numberOfIterations, algorithmCode, randomString);
     }
     catch (NoSuchAlgorithmException ex) {
       Logger.getLogger(EncryptionHelperUtl.class.getName()).log(Level.SEVERE, null, ex);
     }
     return userPassword.toString();
   }
   
   private static StringBuilder doEncryption(String userName, char[] userEnteredPassword, String numberOfIterations, String algorithmCode, String randomString) throws NoSuchAlgorithmException
   {
     String salt = userName.concat(randomString);
     char[] saltArray = salt.toCharArray();
     MessageDigest md = null;
     md = MessageDigest.getInstance(Algorithm.getAlgorithmName(algorithmCode));
     char[] encryptedPasswordSaltArray = new char[userEnteredPassword.length + saltArray.length];
     System.arraycopy(userEnteredPassword, 0, encryptedPasswordSaltArray, 0, userEnteredPassword.length);
     System.arraycopy(saltArray, 0, encryptedPasswordSaltArray, userEnteredPassword.length, saltArray.length);
     String str = String.valueOf(encryptedPasswordSaltArray);
     byte[] encryptedPasswordByte = str.getBytes();
     int iterations = Integer.parseInt(numberOfIterations);
     for (int i = 0; i < iterations; i++) {
       encryptedPasswordByte = md.digest(encryptedPasswordByte);
     }
     
     StringBuilder userPassword = new StringBuilder(numberOfIterations);
     userPassword.append(algorithmCode);
     userPassword.append(randomString);
     userPassword.append(new Base64(-1).encodeToString(encryptedPasswordByte));
     
     return userPassword;
   }
   
   public static boolean verifyPassword(String userName, char[] encryptedPassword, char[] userEnteredPassword, boolean isPasswordEncrypted)
   {
     if ((StringHelperUtl.isEmpty(userName)) || (encryptedPassword.length == 0) || (userEnteredPassword.length == 0)) {
       return false;
     }
     char[] userPassword = userEnteredPassword;
     if (!isPasswordEncrypted) {
       try {
         userPassword = encryptPassword(userName, encryptedPassword, userEnteredPassword);
       }
       catch (Exception localException) {
         return false;
       }
     }
     return Arrays.equals(encryptedPassword, userPassword);
   }
   
   public static String digest(String text)
   {
     if (text == null) {
       return null;
     }
     try {
       MessageDigest md5 = MessageDigest.getInstance("MD5");
       md5.update(text.getBytes());
       BigInteger bigInt = new BigInteger(1, md5.digest());
       return bigInt.toString(16);
     }
     catch (NoSuchAlgorithmException localNoSuchAlgorithmException) {}
     return null;
   }

   public static String generateMd5Hash(Serializable serializableObject)
   {
     if (serializableObject == null) {
       return null;
     }
     String byteArrayString = null;
     try {
       ByteArrayOutputStream byteArrayStream = new ByteArrayOutputStream();
       ObjectOutputStream outputStream = null;
       try {
         outputStream = new ObjectOutputStream(byteArrayStream);
         outputStream.writeObject(serializableObject);
         outputStream.close();
       }
       finally {
         outputStream.close();
         byteArrayStream.close();
       }
       byteArrayString = byteArrayStream.toString();
     }
     catch (IOException e) {
       throw new RuntimeException(e);
     }
     
 
     return digest(byteArrayString);
   }
   
   public static String generateSecureRandomNumber()
   {
     String randomString = "0000000000000000";
     
     try
     {
       SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
       StringBuilder randomNumber = new StringBuilder();
       for (int x = 1; x <= 16; x++) {
         randomNumber = randomNumber.append(new Integer(secureRandom.nextInt(10)).toString());
       }
       randomString = randomNumber.toString();
     }
     catch (NoSuchAlgorithmException exception) {
       Logger.getLogger(EncryptionHelperUtl.class.getName()).log(Level.SEVERE, null, exception);
     }
     return randomString;
   }
 }