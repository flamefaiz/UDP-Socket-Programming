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
import java.util.ArrayList;
import java.security.*;
import javax.crypto.*;
import java.net.InetAddress;
import java.util.Collections;
import java.util.Scanner;

public class Alice  {
static BigInteger p;
static BigInteger g;
static String HashedAlpha = "";
static BigInteger gbmodp;
static int NonceB = 0;
static String BobMessage = "";
static String BobHash = "";
static BigInteger SK;
static final String LINE =("-------------------------------------------------------");

    public static void main(String[] args) throws SocketException, UnknownHostException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException 
    {
        DatagramSocket ds=new DatagramSocket(3456);
        System.out.println("Server Started...");
        String localDir = System.getProperty("user.dir");
        readFile(localDir + "\\Parameters.txt");
                byte b[] = new byte[1000];
                DatagramPacket BobCheck = new DatagramPacket(b,b.length);
                ds.receive(BobCheck);
                String str = new String(BobCheck.getData(),0,BobCheck.getLength());
                String comparestr = "Bob";
                boolean HandshakeSuccess = false;
                
                if(str.equals("Bob"))
                {
                    while(HandshakeSuccess == false)
                    {
                        System.out.println("Received:"+str);
                        System.out.println("");

                        //Send GaModP to Bob. Step 1 - Part 2
                        int a = ((int) (Math.random()*(11 - 2))) + 2;
                        BigInteger gamodp = g.modPow(BigInteger.valueOf(a), p);
                        String msg = HashedAlpha + "%%" + p + "%%" + g + "%%" + gamodp;
                        RC4 rc = new RC4();
                        String key = "Sundeep";
                        String encrypted = rc.Encrypt(msg,key);
                        byte EncryptBytes [] = encrypted.getBytes();
                        InetAddress ia = InetAddress.getByName("127.0.01");
                        DatagramPacket Sendgamodp = new DatagramPacket(EncryptBytes,EncryptBytes.length, ia, BobCheck.getPort());
                        ds.send(Sendgamodp);
                        System.out.println(LINE);
                        System.out.println("Step 1 - Part 2, Send GaModP to Bob.");
                        System.out.println("Hashed Password is: " + HashedAlpha);
                        System.out.println("P value is: " + p);
                        System.out.println("G value is: " + g);
                        System.out.println("GaModP value is: " +gamodp);
                        System.out.println("");
						System.out.print("Encrypted Packets send...\n"); 
						System.out.println(LINE);
						

                        //Receiving GBModP from Bob. Step 1 - Part 3
                        key = HashedAlpha;
                        byte b2[] = new byte[1000];
                        DatagramPacket ReceiveGBModp = new DatagramPacket(b2,0,b2.length);
                        ds.receive(ReceiveGBModp);
                        String EncryptedString = new String(ReceiveGBModp.getData(),0,ReceiveGBModp.getLength());
                        System.out.println("Received: "+EncryptedString);
                        String DecryptedString = rc.Encrypt(EncryptedString,key);
                        System.out.println("");
                        System.out.println("Step 1 - Part 3, Receiving GBModP from Bob");
						System.out.println(DecryptedString);
						String[] parameterArray = DecryptedString.split("\\%%+");
					    HashedAlpha = parameterArray[0];
					    String temp = parameterArray[1];
					    gbmodp = new BigInteger(temp);

					    System.out.println("P value is: "+ p);
					    System.out.println("g value is: "+ g);
					    System.out.println("Hashed alpha value is: "+ HashedAlpha);
					    System.out.println("GbModP value is: "+ gbmodp);
                        System.out.println(LINE);

                        //Sending NonceA to Bob. Step 1 - Part 4
                        SK = gbmodp.modPow(BigInteger.valueOf(a),p);
                        String HashSK = HashThisString(SK.toString());
                        key = HashedAlpha;
                        int NonceA = ((int) (Math.random()*(10000 - 1))) + 1;
                        String nonce = HashSK + "%%" + NonceA;
                        String EncryptedNonce = rc.Encrypt(nonce,key);
                        byte NonceBytes [] = EncryptedNonce.getBytes();
                        InetAddress iaa = InetAddress.getByName("127.0.01");
                        DatagramPacket SendNonce = new DatagramPacket(NonceBytes,NonceBytes.length, iaa, BobCheck.getPort());
                        ds.send(SendNonce);

                        System.out.println("");
                        System.out.println("Step 1 - Part 4, Sending NonceA to Bob");
                        System.out.println("Nonce A Value is: " + NonceA);
                        System.out.println("The Shared key is: " + HashSK);
						System.out.print("Encrypted Packets send...\n"); 
                        System.out.println(LINE);


                        //Receiving NonceB from Bob. Step 1 - Part 5
                        byte b3[] = new byte[1000];
                        DatagramPacket ReceiveNonce = new DatagramPacket(b3,0,b3.length);
                        ds.receive(ReceiveNonce);
                        String ReceiveEncryptedNonce = new String(ReceiveNonce.getData(),0,ReceiveNonce.getLength());
                        System.out.println("Received: "+ReceiveEncryptedNonce);
                        String DecryptedNonce = rc.Encrypt(ReceiveEncryptedNonce,key);
                        DelimitNonce(DecryptedNonce);  
                        System.out.println("");
                        System.out.println("Step 1 - Part 5, Receiving NonceB from Bob");
                        System.out.println("Nonce B Value is: " + NonceB);
                        System.out.println("The Shared key is: " + HashSK);
                        System.out.println(LINE);

                        //Sending Incremented NonceB to Bob. Step 1 - Part 6
                        NonceB++;
                        nonce = SK + "%%" + NonceB;
                        String EncryptedNonceB = rc.Encrypt(nonce,key);
                        byte NonceBytesB [] = EncryptedNonceB.getBytes();
                        InetAddress ia2 = InetAddress.getByName("127.0.01");
                        DatagramPacket SendNonceB = new DatagramPacket(NonceBytesB,NonceBytesB.length, ia2, BobCheck.getPort());
                        ds.send(SendNonceB);
                        System.out.println("");
                        System.out.println("Step 1 - Part 6, Sending Incremented NonceB to Bob");
                        System.out.println("Incremented Nonce B Value is: " + NonceB);
                        System.out.println("The Shared key is: " + HashSK);
                        System.out.print("Encrypted Packets send...\n"); 
						System.out.println(LINE);
                        HandshakeSuccess = true;
                    }
                    
                    boolean Connected = true;
                    while (Connected == true)
                    {
                        //Step 2 - Part 1 (Alice send to Bob)
                        RC4 rc2 = new RC4();
                        String HashSK = HashThisString(SK.toString());
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
                        DatagramPacket SendEncryptedC = new DatagramPacket(SendC,SendC.length, iac, BobCheck.getPort());
                        ds.send(SendEncryptedC);
                        System.out.println("");
                        System.out.println("Step 2 - Part 1 (Alice send to Bob)");
                        System.out.println("Hashed Message is: " + hash);
                        System.out.println("Mhash is: " +Mhash);
                        System.out.println("Mhash encrypted: " + C);
                        System.out.print("Encrypted Packets send...\n");
						System.out.println(LINE);

                        //Step2 - Part 3 (Alice receive from Bob)
                        byte b6[] = new byte[1000];
                        DatagramPacket ReceiveC = new DatagramPacket(b6,0,b6.length);
                        ds.receive(ReceiveC);
                        String ReceiveEncryptedC = new String(ReceiveC.getData(),0,ReceiveC.getLength());
                        String DecryptedC = rc2.Encrypt(ReceiveEncryptedC,HashSK);
                        DelimitSK(DecryptedC);
                        String AliceHash = HashThisString(HashSK + "%%" + BobMessage + "%%" + HashSK);
                        if(AliceHash.equals(BobHash))
                           {
                            System.out.println("Hash Strings match. M is accepted");
							System.out.println("Message M is: " + BobMessage);
                           }
                    }
                    
                    
                    
                }
                
    }
               
    
                public static void readFile(String filename) throws IOException
                {
                    ArrayList<String> parameterList = new ArrayList<String>();
                    BufferedReader br = new BufferedReader(new FileReader(filename));
                    try 
                    {
                        String line;
                           while ((line = br.readLine()) != null) 
                           {
                                parameterList.add(line);
                           }
                    }
                    finally 
                    {
                     br.close();
                    } 
                    String temp = parameterList.get(0);
                    p=new BigInteger(temp);
                    temp = parameterList.get(1);
                    g=new BigInteger(temp);
                    HashedAlpha = parameterList.get(2);

                }
                
                
                public static void DelimitNonce(String text)
                {
                    String[] parameterArray = text.split("\\%%+");
                    String temp = parameterArray[2];
                    NonceB = Integer.valueOf(temp);
                }
                
                public static void DelimitSK(String text)
                {
                    String[] parameterArray = text.split("\\%%+");
                    BobMessage = parameterArray[0];
                    BobHash = parameterArray[1];

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


    
    