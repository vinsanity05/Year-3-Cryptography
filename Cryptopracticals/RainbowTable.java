package Cryptopracticals;

/*
 * @author vemvmacpro
 * This is for Practical 7 / task 4 and called Implementing Rainbow Tables to 
 * crack password - this is to generate the table
 */


import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javax.swing.JProgressBar;


public class RainbowTable {

    public String character_set;
    public volatile int length_of_password;
    public volatile int length_of_chain;
    public volatile int number_of_chains;
    public BigInteger modulo;
    public HashMap<String, String> rain_table;
    public volatile int progress;
    public volatile int done;
    public String filename;
    public JProgressBar progress_bar;
    private static SecureRandom random;

    
    //The 'this' keyword is used to refer to the current object in a constructor
    
    public RainbowTable(String character_set, int password_length, int length_of_chain, int number_of_chains) 
    {
        this.character_set = character_set;
        this.length_of_password = password_length;
        this.length_of_chain = length_of_chain;
        this.number_of_chains = number_of_chains;
        this.filename = "";
        this.modulo = BigInteger.valueOf(0);
        this.done = 0;
        RainbowTable.random = new SecureRandom();
    }
    
    // This will accquire a prime integer depending on the length of the character set and the password 
    
    private BigInteger Accquiring_the_prime()
    {
        BigInteger max = BigInteger.ZERO;

        for (int i = 1; i <= length_of_password; i++)
            max = max.add(BigInteger.valueOf(character_set.length()).pow(i));

        BigInteger prime = max.nextProbablePrime();
        System.out.println("our prime: " + prime);
        
        return prime;
    }
    
    // This coverts the byte array to hex string and used from the practical sheets given
    
    private static String convert_to_hex(byte[] data) 
    { 
        StringBuilder buf = new StringBuilder();

        int i = 0;
        while (i < data.length) {
            int halfbyte = (data[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do
            {
                if ((0 > halfbyte) || (halfbyte > 9)) {
                    buf.append((char) ('a' + (halfbyte - 10)));
                } else {
                    buf.append((char) ('0' + halfbyte));
                }

                halfbyte = data[i] & 0x0F;
            }
            while(two_halfs++ < 1);
            i++;
        }
        return buf.toString();
    } 
    
    //This part was from the practical 4, this part was from that worksheet and took code from
    //the appendix that illustrates the PasswordDemo
    
    public static String SHA1_hash(String text) throws NoSuchAlgorithmException, UnsupportedEncodingException  
    { 
	MessageDigest md;
        md = MessageDigest.getInstance("SHA-1");
        byte[] sha1hash;
        md.update(text.getBytes(StandardCharsets.ISO_8859_1), 0, text.length());
        sha1hash = md.digest();
        return convert_to_hex(sha1hash);
    } 

    // This is a reduction function to help collisions while making the password
    
    private String reduction(String hash, int position)
    {
        BigInteger index;
        StringBuilder string_build = new StringBuilder();
        BigInteger short_term = new BigInteger(hash, 16);

        short_term = short_term.add(BigInteger.valueOf(position)); // temporary to set the position with the prime
        short_term = short_term.mod(this.modulo); // temporary to set the modulo with the prime 

        // This will create the reduced string 
        if (short_term.intValue() > 0) {
            do {
                index = short_term.mod(BigInteger.valueOf(character_set.length()));
                string_build.append(character_set.charAt(index.intValue()));
                short_term = short_term.divide(BigInteger.valueOf(character_set.length()));
            } while (short_term.intValue() > 0);
        }

        return string_build.toString();
    }
    
    
    // This will generate a random string for the password 
    
    private String random_password_generator(int length_of_password)
    {
       
        random = new SecureRandom();
        
        // This will catch if the password is empty
        if (length_of_password < 1) {
            throw new IllegalArgumentException();
        } else {// This will build the password
            StringBuilder string_build = new StringBuilder(length_of_password);
            int i = 0;
            while (true) {
                if (i >= length_of_password) 
                    break;
                int random_Character_index = random.nextInt(character_set.length());
                char Random_character = character_set.charAt(random_Character_index);
                string_build.append(Random_character);
                i++;
            }
            return string_build.toString();
        }
    }
    

    // This will generate the chain 
    
    private String generating_chain(String start) throws NoSuchAlgorithmException, UnsupportedEncodingException
    {
        String password = start;
        
        int i=0;
        while (i < length_of_chain) {
            password = reduction(SHA1_hash(password),i);
            i++;
        }
        
        return password;
    }
    
   
    // This will generate the Rainbow table
    
    public HashMap<String,String> generating_Rainbow_Table() throws NoSuchAlgorithmException, UnsupportedEncodingException
    {
        // This will begin the internal variables
        String start, key;
        int collisions = 0;
        long inc = 0;        
        rain_table = new HashMap<>(number_of_chains);
        modulo = Accquiring_the_prime(); 
        
        // This will occupy the size of the table
        if (rain_table.size() >= number_of_chains) {
        } else {
            do {
                progress = (number_of_chains / (rain_table.size() + 1)) % 100;

                // This will begin the chain procedure
                start = random_password_generator(length_of_password);
                key = generating_chain(start);
                
                
                //If a key exists, then collision happens and find a new key
                if (!rain_table.containsKey(key)) {
                    
                    // This will modify till its finished and implemented the chain to the table
                    progress_bar.setValue(progress);
                    rain_table.put(key, start);
                    inc = inc + number_of_chains;
                    System.out.println("start: " + start +
                            " key: " + key +
                            " length of password: " + length_of_password +
                            " length of chain: " + length_of_chain +
                            " size: " + rain_table.size());
                } else collisions++;
                
                // If a new key is found then it will be stored, we run through till it is 

            } while (rain_table.size() < number_of_chains);
        }
        
        return rain_table;
    }
    
     //This will write the rainbow table to a file 
    
    public void Rainbow_Table_writingFile(String filename, HashMap<String,String> hash_map)
    {
        String eol = System.getProperty("line.separator");
        System.out.println("numchains: " + number_of_chains + " chainlen: " + length_of_chain + " passlen: " +  length_of_password);
        
        // setup header of the csv file
        try (Writer writer = new FileWriter(filename)) 
        {
            writer.append("magic:RBTL");
            writer.append(eol);

            writer.append("number of chains:");
            writer.append(Integer.toString(number_of_chains));
            writer.append(eol);

            writer.append("length of chains:");            
            writer.append(Integer.toString(length_of_chain));
            writer.append(eol);
            
            writer.append("password length:");            
            writer.append(Integer.toString(length_of_password));
            writer.append(eol);
            
            writer.append("charset:");            
            writer.append(character_set);
            writer.append(eol);
            
          // This will write the file into a csv file 
          for (Map.Entry<String, String> entry : hash_map.entrySet()) 
          {
            writer.append(entry.getKey())
                  .append(',')
                  .append(entry.getValue())
                  .append(eol);
          }
        } 
        catch (IOException ex) 
        {
          ex.printStackTrace(System.err);
        }
    }
    
    // This will read the Rainbow table
    
    public int Rainbow_table_ReadFile(String filename) throws IOException
    {
        rain_table = new HashMap<>(number_of_chains);
        BufferedReader csvReader = new BufferedReader(new FileReader(filename));
        String row;
        int i = 0;
        
        //this will read the line per row
        while ((row = csvReader.readLine()) != null) 
        {
            // This is after the header
            if(i<=4)
            {
                // This is used to read and verify
                String[] data2 = row.split(":");
                System.out.println("start: " + data2[0] + " key: " + data2[1]);
                
                
                if(i!=0) {
                } else if(!data2[1].equals("RBTL"))
                    return -1;
                
                if(i!=1) {
                } else {
                    number_of_chains = Integer.parseInt(data2[1]);
                }
                if(i!=2) {
                } else {
                    length_of_chain = Integer.parseInt(data2[1]);
                }
                if(i!=3) {
                } else {
                    length_of_password = Integer.parseInt(data2[1]);
                }
                if(i!=4) {
                } else {   
                    character_set = data2[1];
                }   
            } else
            {
                String[] data = row.split(",");
                rain_table.put(data[0], data[1]);
                
            }
            
            i++;
        }
        this.modulo = Accquiring_the_prime();
        System.out.println("numchains: " + number_of_chains + " chainlen: " + length_of_chain + " passlen: " + length_of_password + "\ncharset: " + character_set);
        csvReader.close(); // close the csv file
    
        return 0;
    }
    
    // This will find the hashes from the Rainbow Table
    
    public String Rainbow_Table_findingHash(String hash) throws NoSuchAlgorithmException, UnsupportedEncodingException
    {
        String target_hash;
        String pass = null;
        String found_pass = null;
        
        // run the chain back from original hash
        int i= length_of_chain-1;
        while (i >= 0) {
            target_hash = hash;

            // produce the chain to find the password
            int j=i;
            while (j<length_of_chain) {
                pass = reduction(target_hash,j);
                target_hash = SHA1_hash(pass);
                j++;
            }

            // found the password key in the table and target the chain
            if (!rain_table.containsKey(pass)) {
                i--;
                continue;
            }
            found_pass = Rainbow_Table_FindChains(rain_table.get(pass), hash);

            if(found_pass!=null)
                break;
            i--;
        }

        return found_pass;
    }
    
    //This will find the chains in the rainbow table 
    
    public String Rainbow_Table_FindChains(String chain_start, String hash) throws NoSuchAlgorithmException, UnsupportedEncodingException
    {
        String target_hash;
        String pass = chain_start;
        String found_pass = null;
    
        // produce hash of start of the password and start of the search 
        int i = 0;
        while (i < length_of_chain) {
            target_hash = SHA1_hash(pass);

            
            if (!target_hash.equals(hash)) {// if hash is not equals to the password, then it will get reduce again
                pass = reduction(target_hash, i);
                i++;
            } else {
                found_pass = pass; // password will be stored
                break;
            }

        }
    
        return found_pass;
    }
};
