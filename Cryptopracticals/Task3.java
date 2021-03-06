package Cryptopracticals;

/**
 * @author vemvmacpro
 * This is for Practical 4 / task 3 and called SHA1 hash gen/cracker
 */


import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;


public class Task3 extends javax.swing.JFrame {

    private static final String LowerCase = "abcdefghijklmnopqrstuvwxyz";
    private static final String Number = "0123456789";
    private static final String random_string_data = LowerCase + Number;
    private static final SecureRandom random = new SecureRandom();
   
    /**
     * Creates new form NewJFrame and renamed I to Task 3 
     */
    
    public Task3() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jButton1 = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jButton2 = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        jButton3 = new javax.swing.JButton();
        jButton4 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jButton1.setFont(new java.awt.Font("Lucida Grande", 0, 20)); // NOI18N
        jButton1.setText("hash");
        jButton1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jButton1MouseClicked(evt);
            }
        });

        jTextArea1.setColumns(20);
        jTextArea1.setRows(5);
        jScrollPane1.setViewportView(jTextArea1);

        jButton2.setFont(new java.awt.Font("Lucida Grande", 0, 20)); // NOI18N
        jButton2.setText("crack 0-6 pass");
        jButton2.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jButton2MouseClicked(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Lucida Grande", 0, 20)); // NOI18N
        jLabel1.setText("SHA1 hash gen/cracker");

        jTextField1.setHorizontalAlignment(javax.swing.JTextField.LEFT);
        jTextField1.setText("enter text here...");
        jTextField1.setToolTipText("");
        jTextField1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField1ActionPerformed(evt);
            }
        });

        jButton3.setFont(new java.awt.Font("Lucida Grande", 0, 20)); // NOI18N
        jButton3.setText("crack BCH 10 6");
        jButton3.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jButton3MouseClicked(evt);
            }
        });

        jButton4.setFont(new java.awt.Font("Lucida Grande", 0, 18)); // NOI18N
        jButton4.setText("clear");
        jButton4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton4ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(31, 31, 31)
                                .addComponent(jLabel1))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(56, 56, 56)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(jButton3)
                                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(jButton2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(jButton1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))))
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(18, 18, 18)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 367, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(27, 27, 27)
                                .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, 348, javax.swing.GroupLayout.PREFERRED_SIZE))))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(80, 80, 80)
                        .addComponent(jButton4, javax.swing.GroupLayout.PREFERRED_SIZE, 134, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(17, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(44, 44, 44)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, 37, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(68, 68, 68)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jButton1)
                        .addGap(18, 18, 18)
                        .addComponent(jButton2)
                        .addGap(33, 33, 33)
                        .addComponent(jButton3))
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 139, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(38, 38, 38)
                .addComponent(jButton4)
                .addContainerGap(65, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

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

    // This part was from the practical 4, this part was from that worksheet and took code from
    // the appendix that illustrates the PasswordDemo
  
    public static String SHA1(String text)  throws NoSuchAlgorithmException, UnsupportedEncodingException
    {
        MessageDigest md;
        md = MessageDigest.getInstance("SHA-1");
        byte[] sha1hash;
        md.update(text.getBytes(StandardCharsets.ISO_8859_1), 0, text.length());
        sha1hash = md.digest();
        return convert_to_hex(sha1hash);
    }


    // This decodes a syndrome for BCH 10,6 and returns an array of the decoded syndrome
    // Also used from the previous task 

    private int[] decodeSyndrome(int[] d, int mod)
    {
        int [] syndrome = new int[10];

        // This is s1 = (d1+....d10) mod 11
        int i=0;
        while (i<10) {
            syndrome[0] += d[i];
            i++;
        }
        syndrome[0] %= mod;

        // This is s2 = (d1+2*d2+3....+10*d10) mod 11
        syndrome[1] = (d[0]+2 *
                d[1]+3 *
                d[2]+4 *
                d[3]+5 *
                d[4]+6 *
                d[5]+7 *
                d[6]+8 *
                d[7]+9 *
                d[8]+10 *
                d[9])%mod;

        // This is s3 = (d1+4*d2....+4*d9+d10) mod 11

        syndrome[2]=(d[0] + 4 *
                d[1] + 9 *
                d[2] + 5 *
                d[3] + 3 *
                d[4] + 3 *
                d[5] + 5 *
                d[6] + 9 *
                d[7] + 4 *
                d[8] +
                d[9]) % mod;

        // This is  s4 = (d1+8*d2.....+3*d9+10*d10) mod 11

        syndrome[3]=(d[0] + 8 *
                d[1] + 5 *
                d[2] + 9 *
                d[3] + 4 *
                d[4] + 7 *
                d[5] + 2 *
                d[6] + 6 *
                d[7] + 3 *
                d[8] + 10 *
                d[9]) % mod;


        return syndrome;
    }

//This returns the correct password ??by matching the password from the hash.
    
    private String hash_crack(String hash)
    {
        String password = null,hashGuess = "";
        char a,b,c,d,e,f;

        // This will loop for the 6 characters 
        int z = 0;
        while (z < 36) {
            int y = 0;
            while (y < 36) {
                int x = 0;
                while (x < 36) {
                    int w = 0;
                    while (w < 36) {
                        int v = 0;
                        while (v < 36) {
                            int u = 0;
                            while (u < 36) {
                                // this will give a match!
                                if ((hash.compareTo(hashGuess)) != 0) {

                                    a = random_string_data.charAt(u);
                                    b = random_string_data.charAt(v);
                                    c = random_string_data.charAt(w);
                                    d = random_string_data.charAt(x);
                                    e = random_string_data.charAt(y);
                                    f = random_string_data.charAt(z);

                                    password = String.valueOf(a);
                                    
                                    
                                    // this all appends to a string 

                                    if (v <= 0) {
                                    } else {
                                        password = String.valueOf(a) + b;
                                    }
                                    if (w <= 0) {
                                    } else {
                                        password = String.valueOf(a) + b + c;                                       
                                    }
                                    if (x <= 0) {
                                    } else {
                                        password = String.valueOf(a) + b + c + d;                                       
                                    }
                                    if (y <= 0) {
                                    } else {
                                        password = String.valueOf(a) + b + c + d + e;                                      
                                    }
                                    if (z <= 0) {
                                    } else {
                                        password = String.valueOf(a) + b + c + d + e + f;                                       
                                    }


                                    try {
                                        hashGuess = SHA1(password);
                                    } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
                                        Logger.getLogger(Task3.class.getName()).log(Level.SEVERE, null, ex);
                                    }
                                }

                                // This will iterate the password attempt
                                else {
                                    return password;
                                }

                                u++;
                            }
                            v++;
                        }
                        w++;
                    }
                    x++;
                }
                y++;
            }
            z++;
        }
        return "";
    }

    //This will generate a full BCH,  bruteforce the BCH  and returns
    //This is all from lecture and tutorial slides from week 2 
    
    String generating_BCH(int num)
    {
        int[] d = new int[10];
        String out = "";
        String str = String.format("%06d", num); 

        for(int i = 5; i >= 0; i--)
            d[i]= str.charAt(i)-48;

        //d7 = (4*d1+10*...+7*d6) mod 11
        d[6]= (4 * d[0] +
                10 * d[1] +
                9 * d[2] +
                2 * d[3] +
                d[4]     +
                7 * d[5]
        ) % 11;

        //d8 = (7*d1+8*...+6*d6) mod 11
        d[7]= (7 * d[0] +
                8 * d[1] +
                7 * d[2] +
                d[3]     +
                9 * d[4] +
                6 * d[5]
        ) % 11;

        //d9 = (9*d1+...d5+7*d6) mod 11
        d[8]= (9 * d[0] +
                d[1]     +
                7 * d[2] +
                8 * d[3] +
                7 * d[4] +
                7 * d[5]
        ) % 11;

        //d10 = (d1+2*d2+...*d5+d6) mod 11
        d[9] =(d[0]     +
                2 * d[1] +
                9 * d[2] +
                10 * d[3] +
                4 * d[4] +
                d[5]
        ) % 11;

        int i = 0;
        while (i < 10) {
            if (d[i] != 10) {
                out += Integer.toString(d[i]);
            } else {
                out += 'x';
            }
            i++;
        }

        return out;
    }

    //This will match the correct BCH from the hash
   
    private String BCH_Cracking(String hash)
    {
        String password,guessing_hash = "";

        for(int z = 999999; z >= 0; z--)
        {

            password = generating_BCH(z);
           

            try {
                guessing_hash = SHA1(password);
            } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
                Logger.getLogger(Task3.class.getName()).log(Level.SEVERE, null, ex);
            }

            if ((hash.compareTo(guessing_hash)) != 0) {
                continue;
            }
            return password;

        }

        return "";
    }

//By having a boolean, this will make sure if the BCH is correct and
    //verify whether if it is valid or not
   
    private boolean BCH_verify(String bch)
    {
        boolean verify;
        int[] d = new int[10];
        int[] syndrome;

        // While loop to parse the code to our array
        int i = 0;
        while (i < 10) {
            d[i] = Integer.parseInt(String.valueOf(bch.charAt(i)));
            i++;
        }

        //This will result in a decoded version of our syndromes
        syndrome = decodeSyndrome(d,11);


        // When all decoded syndromes are clear - no error will only produce
        if (syndrome[0] + syndrome[1] + syndrome[2] + syndrome[3] != 0) {
            System.out.println("it is false");
            verify = false;
        } else {
            System.out.println("it is true");
            verify = true;
        }
        return verify;
    }


 // This will produce the hash and will verify and validate the code too
  
    private void Produce_hash()
    {

        String s = jTextField1.getText();
        jTextArea1.setText("");

        // The password must be 1-6 characters long, or if its 10 we continue
        if(s.length() == 0 || (s.length() > 6 && s.length() != 10))
        {
            jTextArea1.setText("Enter a valid BCH 10,6 or a 6 character password please!");
        }
        // if its 10 characters long then it can be a BCH code, so check if all numeric
        else if(s.length() == 10 && Pattern.matches("[a-zA-Z]+", s))
        {
            jTextArea1.setText("Enter a BCH 10,6 please!");
        }
   
        else
        {

            // Invalid BCH number
            if(s.length() == 10)
            {
                if(!BCH_verify(s))
                {
                   
                    jTextArea1.setText("Enter a valid BCH 10,6 number please!");
                }
            }
            else
            {
                try
                {
                    jTextArea1.setText(
                            "string: " + s +"\n" +
                                    "hash: " + SHA1(s) +"\n"
                    );

                } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
                    Logger.getLogger(Task3.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    
    //This cracks the password, however the limit is only 6 character long and lower case 
    
    private void crack_password()
    {
        jTextArea1.setText("");

        String hash = jTextField1.getText();
        if(hash.length() != 40)
        {
            jTextArea1.setText("Enter a valid hash to crack please!");
            return;
        }

        
       
    // These are examples for to crack when pressing the 0-6 password button
    // "c2543fff3bfa6f144c2f06a7de6cd10c0b650cae",
    // "b47f363e2b430c0647f14deea3eced9b0ef300ce",
    // "e74295bfc2ed0b52d40073e8ebad555100df1380",
        
        
        //This will check how long the duration for it to be cracked in milliseconds
        long start = System.currentTimeMillis();
        String password = hash_crack(hash);

        long end = System.currentTimeMillis();
        long duration = (end - start);
        
        //This will print out the output in the system if there is a password
        if(!password.equals(""))
        {
            jTextArea1.setText("password:"+password+"\n"+ " This was found in: "+ (duration) + " milliseconds");
            System.out.print("password:"+password+"\n"+ " This was found in: "+ (((duration)/1000)/60) + " minutes & "+((duration)/1000)+ " seconds"+"\n");
            System.out.print("total milliseconds: "+ (duration) +"\n");
        }
        else
            jTextArea1.setText("This password is not found.");
        //  }

    }

    //This is for only valid BCH 10,6 to crack 
    //"902608824fae2a1918d54d569d20819a4288a4e4" 
    //"88d0b34055b79644196fce25f876bc1a5ef654d3",
    //"5b8f495b7f02b62eb228c5dbece7c2f81b60b9a3"
 
    private void BCH_cracking()
    {
        jTextArea1.setText("");

      
        String hash = jTextField1.getText();
        if(hash.length() == 40)
        {
        } else {
            jTextArea1.setText("Enter a valid hash to crack please!");
            return;
        }

        // This will check how long the duration for it to be cracked in milliseconds
        long start = System.currentTimeMillis();
        String password = BCH_Cracking(hash);
        
        long end = System.currentTimeMillis();
        long duration = (end - start);

        //This will print out the output in the system if there is a password
        if(!password.equals(""))
        {
            jTextArea1.setText("password:"+password+"\n"+ "This was found in: "+ (duration) + " milliseconds");
            System.out.print("password:"+password+"\n"+ "This was found in: "+ (((duration)/1000)/60) + " minutes & "+((duration)/1000)+ " seconds"+"\n");
            System.out.print("total milliseconds: "+ (duration) +"\n");
        }
        else
            jTextArea1.setText("This password was not found.");
        //  }

    }

//this helps it clear the text fields and text area

    private void clear_user_interface()
    {
        jTextField1.setText("");
        jTextArea1.setText("");
    }

    
    
    private void jButton1MouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton1MouseClicked
        Produce_hash();
    }//GEN-LAST:event_jButton1MouseClicked

                 
    private void jButton2MouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton2MouseClicked
        crack_password();
    }//GEN-LAST:event_jButton2MouseClicked

   
    private void jButton3MouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton3MouseClicked
        BCH_cracking();
    }//GEN-LAST:event_jButton3MouseClicked

    private void jTextField1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextField1ActionPerformed

    private void jButton4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton4ActionPerformed
        // TODO add your handling code here:
        clear_user_interface(); 
    }//GEN-LAST:event_jButton4ActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Task3.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Task3.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Task3.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Task3.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Task3().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea jTextArea1;
    private javax.swing.JTextField jTextField1;
    // End of variables declaration//GEN-END:variables
}
