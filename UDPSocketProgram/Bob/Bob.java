/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Scanner;
import java.security.*;
import javax.crypto.*;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;

public class Bob {
    
        static String parameterArray [] = new String[4];
		static String nonceArray [] = new String[4];
        static BigInteger p;
        static BigInteger g;
        static String HashedAlpha = "";
        static BigInteger gamodp;
        static BigInteger SK;
        static int NonceA = 0;
        static int NonceB = 0;
        static String AliceMessage = "";
        static String AliceHash = "";
		static final String LINE =("-------------------------------------------------------");

    public static void main(String[] args) throws SocketException, UnknownHostException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException  {
        
        String AlphaNum = "";
        Boolean HandshakeSuccess = false;
        
        DatagramSocket ds = new DatagramSocket();
        System.out.println("Client Started...");
        String localDir = System.getProperty("user.dir");
        BufferedReader br = new BufferedReader(new FileReader(localDir + "\\BobPW.txt"));
        try {
            String line;
           for(int i = 0; i < 3; i++)
           {
               while ((line = br.readLine()) != null) {
               // process the line
               AlphaNum = line;
            }
           }
        } finally {
            br.close();
                  }        
        
        System.out.print("Please Enter PW: ");
                    Scanner pw = new Scanner(System.in);
                    String msg = pw.nextLine();
                    boolean validator = true;
                    while (validator == true)
                    {
                        if(msg.equals(AlphaNum))
                        {
                            validator = false;
                        }
                        else
                        {
                            System.out.print("Password is wrong. Please Reenter: ");
                            msg = pw.nextLine();
                        }
                    }
                        
                        String str = "Bob";
                        byte b1[] = str.getBytes();
                        InetAddress ia = InetAddress.getByName("127.0.01");
                        DatagramPacket SendAlice = new DatagramPacket(b1, b1.length, ia, 3456);
                        ds.send(SendAlice);
                        System.out.println("Step 1 - Part 1");
                        System.out.printf("Sending %s to Alice\n", str);
                        System.out.print("Packets send...\n");
						System.out.println(LINE);
                        
                        while(HandshakeSuccess == false)
                           {
                                    //Receiving GaModP From Alice. Step 1 - Part 2
                                    RC4 rc = new RC4();
                                    String key = "Sundeep";
                                    byte b2[] = new byte[1000];
                                    DatagramPacket ReceiveGaModP = new DatagramPacket(b2,0,b2.length);
                                    ds.receive(ReceiveGaModP);
                                    String EncryptedString = new String(ReceiveGaModP.getData(),0,ReceiveGaModP.getLength());
                                    String DecryptedString = rc.Encrypt(EncryptedString,key);
                                    DelimitAndStore(DecryptedString);
                                    System.out.println("");
                                    System.out.println("Received: "+EncryptedString);
                                    System.out.println("Step 1 - Part 2, Receiving GaModP From Alice");
                                    System.out.println("Hashed Password is: " + HashedAlpha);
                                    System.out.println("P value is: " + p);
                                    System.out.println("G value is: " + g);
                                    System.out.println("GaModP value is: " +gamodp);
                                    System.out.println(LINE);
                                    
                                    
                                    //Sending GBModP to Alice. Step 1 - Part 3
                                    key = HashedAlpha;
                                    int b = ((int) (Math.random()*(11 - 2))) + 2;
                                    BigInteger gbmodp = g.modPow(BigInteger.valueOf(b), p);
                                    String encrypt = HashedAlpha + "%%" + gbmodp;
                                    String encrypted = rc.Encrypt(encrypt,key);
                                    byte EncryptBytes [] = encrypted.getBytes();
                                    InetAddress iaa = InetAddress.getByName("127.0.01");
                                    DatagramPacket SendGbModP = new DatagramPacket(EncryptBytes,EncryptBytes.length, iaa, SendAlice.getPort());
                                    ds.send(SendGbModP);
									System.out.println("");
                                    System.out.println("Step 1 - Part 3, Sending GBModP to Alice");
                                    System.out.println("P value is: "+ p);
                                    System.out.println("g value is: "+ g);
                                    System.out.println("Hashed alpha value is: "+ HashedAlpha);
                                    System.out.println("GbModP value is: "+ gbmodp);
                                    System.out.print("Packets send...\n");
									System.out.println(LINE);
                                    SK = gamodp.modPow(BigInteger.valueOf(b),p);

                                    
                                    //Receiving NonceA from Alice. Step 1 - Part 4
                                    byte b3[] = new byte[1000];
                                    String HashSK = HashThisString(SK.toString());
                                    DatagramPacket ReceiveNonce = new DatagramPacket(b3,0,b3.length);
                                    ds.receive(ReceiveNonce);
                                    String EncryptedNonce = new String(ReceiveNonce.getData(),0,ReceiveNonce.getLength());
                                    String DecryptedNonce = rc.Encrypt(EncryptedNonce,key);
                                    String[] nonceArray = DecryptedNonce.split("\\%%+");
									String Noncetemp = nonceArray[1];
									NonceA = Integer.valueOf(Noncetemp);
                                    System.out.println("");
                                    System.out.println("Received: "+EncryptedNonce);
                                    System.out.println("Step 1 - Part 4, Receiving NonceA from Alice");
                                    System.out.println("Nonce A Value is: " + NonceA);
                                    System.out.println("The Shared key is: " + HashSK);
                                    System.out.println(LINE);
                                    
                                    //Sending NonceB to Alice. Step 1 - Part 5
                                    NonceB = ((int) (Math.random()*(10000 - 1))) + 1;
                                    NonceA++;
                                    String nonce = HashSK + "%%" + NonceA + "%%" + NonceB;
                                    String EncryptedSendNonce = rc.Encrypt(nonce,key);
                                    byte NonceBytes [] = EncryptedSendNonce.getBytes();
                                    InetAddress iab = InetAddress.getByName("127.0.01");
                                    DatagramPacket SendNonce = new DatagramPacket(NonceBytes,NonceBytes.length, iaa, SendAlice.getPort());
                                    ds.send(SendNonce);
                                    
                                    System.out.println("");
                                    System.out.println("Step 1 - Part 5, Sending NonceB to Alice");
                                    System.out.println("Nonce B Value is: " + NonceB);
                                    System.out.println("The Shared key is: " + HashSK);
                                    System.out.print("Encrypted Packets send...\n");
									System.out.println(LINE);
                                    
                                    //Receiving NonceB from Alice
                                    byte b4[] = new byte[1000];
                                    DatagramPacket ReceiveNonceB = new DatagramPacket(b4,0,b4.length);
                                    ds.receive(ReceiveNonceB);
                                    String ReceiveEncryptedNonceB = new String(ReceiveNonceB.getData(),0,ReceiveNonceB.getLength());
                                    String DecryptedNonceB = rc.Encrypt(ReceiveEncryptedNonceB,key);
                                    String[] parameterArray = DecryptedNonceB.split("\\%%+");
                                    String temp = parameterArray[1];
                                    if(Integer.valueOf(temp) == NonceB + 1)
                                    {
                                        System.out.println("");
                                        System.out.println("Received: "+ReceiveEncryptedNonceB);
                                        System.out.println("Step 1 - Part 6, Receiving NonceB from Alice");
                                        System.out.println("Incremented Nonce B Value is: " + (NonceB + 1));
                                        System.out.println("The Shared key is: " + HashSK);
                                        System.out.println(LINE);
                                        HandshakeSuccess = true;
                                    }
                                    else
                                    {   
                                        System.out.println("Login Failed");
                                        ds.close();
                                        break;
                                    }
                           }
                                    
                        boolean Connected = true;
                        while (Connected == true)
                        {
                                    //Step 2 - Part 2 (Receiving from Alice)
                                    RC4 rc2 = new RC4();
                                    String HashSK = HashThisString(SK.toString());
                                    byte b5[] = new byte[1000];
                                    DatagramPacket ReceiveC = new DatagramPacket(b5,0,b5.length);
                                    ds.receive(ReceiveC);
                                    String ReceiveEncryptedC = new String(ReceiveC.getData(),0,ReceiveC.getLength());
                                    String DecryptedC = rc2.Encrypt(ReceiveEncryptedC,HashSK);
                                    DelimitSK(DecryptedC);
                                    String BobHash = HashThisString(HashSK + "%%" + AliceMessage + "%%" + HashSK);
                                    if(AliceHash.equals(BobHash))
                                    {
                                        System.out.println("Hash Strings match. M is accepted");
                                        System.out.println("Message M is: " + AliceMessage);
                                    }
                                    
                                    //Step 2 - Part 4 (Sending to Alice)
                                    System.out.printf("Please enter text to be sent: ");
                                    Scanner in = new Scanner(System.in);
                                    String message = in.nextLine();
                                    if(message.equals("exit"))
                                    {
                                        Connected = false;
                                        ds.close();
                                        break;
                                    }
                                    String hash = HashThisString(HashSK + "%%" + message + "%%" + HashSK);
                                    String Mhash = message + "%%" + hash;
                                    String C = rc2.Encrypt(Mhash,HashSK);
                                    byte SendC [] = C.getBytes();
                                    InetAddress iac = InetAddress.getByName("127.0.01");
                                    DatagramPacket SendEncryptedC = new DatagramPacket(SendC,SendC.length, iac, SendAlice.getPort());
                                    ds.send(SendEncryptedC);
                                    System.out.println("");
                                    System.out.println("Step 2 - Part 4");
                                    System.out.println("Hashed Message is: " + hash);
                                    System.out.println("Mhash is: " +Mhash);
                                    System.out.println("Mhash encrypted: " + C);
                                    System.out.print("Encrypted Packets send...\n");
									System.out.println(LINE);
									
                                
                            }
    }
    
        
    
    public static void DelimitAndStore(String text) {
    
          String[] parameterArray = text.split("\\%%+");
          String temp = parameterArray[1];
          p=new BigInteger(temp);
          temp = parameterArray[2];
          g=new BigInteger(temp);
          HashedAlpha = parameterArray[0];
          temp = parameterArray[3];
          gamodp = new BigInteger(temp);
}
    
    
    public static void DelimitSK(String text)
    {
        String[] parameterArray = text.split("\\%%+");
        AliceMessage = parameterArray[0];
        AliceHash = parameterArray[1];
          
    }
    
    public static String HashThisString(String input) 
    { 
        try { 
            // getInstance() method is called with algorithm SHA-1 
            MessageDigest md = MessageDigest.getInstance("SHA-1"); 

            // digest() method is called 
            // to calculate message digest of the input string 
            // returned as array of byte 
            byte[] messageDigest = md.digest(input.getBytes()); 

            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 

            // Convert message digest into hex value 
            String hashtext = no.toString(16); 

            // Add preceding 0s to make it 32 bit 
                while (hashtext.length() < 32) { 
                       hashtext = "0" + hashtext; 
                        } 

                        // return the HashText 
                    return hashtext; 
                    } 

                    // For specifying wrong message digest algorithms 
                catch (NoSuchAlgorithmException e) { 
                throw new RuntimeException(e); 
                    } 
    } 
   
        
    
}

class RC4 {
    public static String Encrypt(String plainText,String key){
        String cipher="";
        ArrayList<Character> keys = generateKeys(key);
        int i=0;
        for(char c:plainText.toCharArray()){
            cipher+=(char)(keys.get(i%keys.size())^c);
        }
        return cipher;
    }
    private static ArrayList<Character> generateKeys(String key){
        ArrayList<Character> s=new ArrayList<>(256);
        ArrayList<Character> keys=new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            s.add(i,(char)i) ;
            keys.add(i,key.charAt(i%key.length()));
        }
        int    j = 0; 
        for (int i = 0;i<256;++i){ 
            j = (j + s.get(i) + keys.get(i))% 256; 
            Collections.swap(s,i,j); 
        } 
    
        int i=0,index;
        j = 0;
        for (int k = 0; k < 256; k++) {
            i = (i + 1)% 256; 
            j = (j + s.get(i))% 256; 
            Collections.swap(s,i,j); 
            index = (s.get(i) + s.get(j))% 256; 
            keys.set(i,s.get(index));
        } 
        return keys;
    }
}

