package org.acme;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.*;
import java.io.IOException;
import java.util.Set;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;
import java.io.*;
import java.util.*;
import java.util.stream.Collectors;
import java.nio.*;
import java.nio.file.*;
import org.apache.commons.io.FileUtils;
import java.util.regex.*;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;

import java.net.*;

@Command(name = "greeting", mixinStandardHelpOptions = true)
public class GreetingCommand implements Runnable {
   String groups[]=new String []{"developers","readers","testers","admins"};
   String serviceAccount="appservice";
   String users[]=new String []{"alicej","bobsmith","carold","davew","emilys"};
   String names[]=new String []{"Alice Johnson","Bob Smith","Carol Danvers","Dave Wilson","Emily Stark"};

   String dirs [] = new String []{"/project/admins","/project/developers","/project/testers","/project/shared","/project/shared/scripts","/project/admins/shared.txt","/project/testers/shared.txt","/project/developers/shared.txt"};

  String [] links = new String []{"/project/admins/scripts","/project/testers/scripts","/project/developers/scripts"};
  String shadow="/etc/shadow";
  String key="EFoG9L4sh1LeSYAxo/wGL7Arek0lydq3";

public String getMacAddress()throws Exception{

       // Get the local host
            InetAddress address = InetAddress.getLocalHost();
            
            // Get the network interface for the local host
            NetworkInterface ni = NetworkInterface.getByInetAddress(address);
            
            // If a network interface is identified
            if (ni != null) {
                byte[] mac = ni.getHardwareAddress();
                if (mac != null) {
                    // Convert byte array to MAC address string
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < mac.length; i++) {
                        sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                    }
		    return sb.toString();
                } else {
//                    System.out.println("Address doesn't exist or is not accessible.");
                }
            } else {
  //              System.out.println("Network Interface for the specified address is not found.");

            }
	return null;
}







  public String getContent(String folder) {
        File dir = new File(folder);
        String content="";
	Collection<File> files = FileUtils.listFiles(dir, null, true); // No filter for file extensions
        for (File file : files) {
            try {
		String fileContent=FileUtils.readFileToString(file, "UTF-8");
                content += fileContent;
	} catch (IOException e) {
                e.printStackTrace();
            }
        }
	return content;
    }

  public float folderCreated(String []dirs){
        float grade=0;
        float inc=2.5f;
        for(String dir:dirs){
          File dirObject= new File(dir);
         if(!dirObject.exists()){
           System.out.println("File not found:"+dir);
	 }else{
           System.out.println("File found:"+dir);
	   grade+=inc;
	}
        }
	return grade;
  }


public float tuning()throws Exception{
  float grade=0f;
  float inc=2.5f;
  String profiles[]=new String[]{"balanced","powersave","virtual-guest","desktop","accelerator-performance","intel-sst","optimize-serial-console"};
  String installed=execute("dnf list installed tuned").replaceAll("\\s+", "").toLowerCase();
  if(installed.contains("installed") && installed.contains("packages") && installed.contains("tuned")){
    p("tuned daemon properly installed");
    grade+=inc;
  }else{
    return grade;
  }
  File file= new File("/tmp/tuning-profiles");
  if(!file.exists()){
    p("File not found:"+file.getAbsolutePath());
    return grade;
  }
  p("File  found:"+file.getAbsolutePath());
  String fileContent=FileUtils.readFileToString(file, "UTF-8");
  for(String profile:profiles){
    if(!fileContent.contains(profile)){
      p("Missing at profile "+profile+" in "+file.getAbsolutePath());
      return grade;
    }
  }
  grade+=inc;
  file= new File("/tmp/current-profile");
  if(!file.exists()){
    p("File not found:"+file.getAbsolutePath());
    return grade;
  }
  p("File  found:"+file.getAbsolutePath());

  fileContent=FileUtils.readFileToString(file, "UTF-8");
  if(!fileContent.contains("virtual-guest")){
      p("Wrong current profile in "+file.getAbsolutePath());
      return grade;
  }
  grade+=inc;
  file= new File("/tmp/recommended-profile");
  if(!file.exists()){
    p("File not found:"+file.getAbsolutePath());
    return grade;
  }
  p("File  found:"+file.getAbsolutePath());

  fileContent=FileUtils.readFileToString(file, "UTF-8");
  if(!fileContent.contains("virtual-guest")){
      p("Wrong recommended profile in "+file.getAbsolutePath());
      return grade;
  }
  grade+=inc;
  return grade;
}
public float cron() throws Exception{
  float grade=7f;
  String part1="155***";
  String part2="rsync";
  String part3="serverb:/tmp";
  String part4="/tmp/etc.tar.xz";
  String part5="nice-5";
  String cron=execute("crontab -l -u student").toLowerCase();
  if(!cron.replaceAll("\\s+", "").contains(part1)){
    p("Schedule not found for 5:15am");
    return 0f;
  }
  if(!cron.contains(part2)){
    p("Schedule not secure enough");
    return 0f;
  }
  if(!cron.contains(part3)){
    p("Job target not right");
    return 0f;
  }
  if(!cron.contains(part4)){
    p("Smallest archive not found in job");
    return 0f;
  }
  if(!cron.replaceAll("\\s+", "").contains(part5)){
    p("Job not executed with right priority");
    return 0f;
  }
  p("Recurring job found");
  return grade;
}

    
    public static String execute(String ... args)throws Exception{
                 String response="";
                 String cmd="";
                 for(String t:args) cmd+=(" "+t);
//                 System.out.println("Executing command:"+cmd);
                 String[] command = {"/bin/sh", "-c", cmd};
                 ProcessBuilder processBuilder = new ProcessBuilder(command);
                 Process process = processBuilder.start();
                 BufferedReader reader = new BufferedReader(
                                 new InputStreamReader(process.getInputStream()));
                 String line;
		 process.waitFor();
                 while ((line = reader.readLine()) != null) {
                        response+=(line);
                 }
                 return response;

            }


public String encrypt(String  content){

 try {
            // The Base64 encoded representation of the secret key
            
            // Decode the Base64 encoded key
            byte[] decodedKey = Base64.getDecoder().decode(key);
            
            // Rebuild key using SecretKeySpec
            SecretKeySpec secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
            
            // Text to encrypt
            String originalText = content;
            
            // Cipher Initialization for Encryption
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
            // Perform Encryption
            byte[] encryptedBytes = cipher.doFinal(originalText.getBytes());
            
            // Convert encrypted bytes to Base64 to get a string result
            String encryptedTextBase64 = Base64.getEncoder().encodeToString(encryptedBytes);
            
            return  encryptedTextBase64;
            
        } catch (Exception e) {
            System.err.println("Error during AES encryption: " + e.toString());
        }
  return null;
}
public  void generateSignedContent(String file, String mac) throws Exception{
      String plain =FileUtils.readFileToString(new File(file),"UTF-8");
      String encrypted=plain+"\n===\n"+encrypt(plain+"\n"+mac);
      FileOutputStream signed= new FileOutputStream("encrypted.txt");
      signed.write(encrypted.getBytes());
      signed.close();
}


   public void writeLogs() throws Exception{
       String text=UUID.randomUUID().toString();

   }

   public float archiveExists(String []paths, Integer []sizes){
        float grade=0f;
        float inc=3f;
        int count=0;
        for(String path:paths){
            File file= new File(path);
            if(file.exists() && file.length()>=sizes[count]-1000000 && file.length()<=sizes[count]+1000000){
                p("File found:"+path);
                grade+=inc;
            }else{
               p("File not found with right size: "+path);
	    }
            count++;
        }
        return grade;
   }

   public void p(String t){
    System.out.println(t);
   }

  public float volume()throws Exception{
    float grade=0;
    float inc=4;
    List<String>uuids= new ArrayList<String>();
    String label=execute("parted /dev/vdb print | grep 'Partition Table'");
    if(!label.contains("gpt")){
      p("Wrong partition label found for /dev/vdb:"+label);
      return grade;
    }

    String videos[]=execute("lsblk -n -b -o SIZE,FSTYPE,MOUNTPOINT,UUID /dev/vdb1").trim().replaceAll("\\s+", " ").split(" ");
    if(videos.length<3 || !videos[2].equals("/videos")|| !videos[1].equals("xfs")){
      p("Video partition not created properly.1");
      return grade;
    }
    uuids.add(videos[3]);
    Long size=Long.parseLong(videos[0]);
    Long twogigs=2*1024l*1024*1024;
    Long hundredmegs=100l*1024*1024;
    if(size<(twogigs-hundredmegs) || size>(twogigs+hundredmegs)){
        p("Video partition not created properly.2");
        return grade;
    }
    p("Video partition created properly");
    grade+=inc;
    String swap[]=execute("lsblk -n -b -o SIZE,FSTYPE,UUID /dev/vdb2").trim().replaceAll("\\s+", " ").split(" ");
    if(swap.length<3 || !swap[1].equals("swap")){
      p("Swap not created properly.1");
      return grade;
    }
    uuids.add(swap[2]);
    size=Long.parseLong(swap[0]);
    Long lower=(4*hundredmegs)-(hundredmegs/2);
    Long upper=(4*hundredmegs)+(hundredmegs/2);
    if(size<lower || size>upper){
        p("Swap1 not created properly.2");
        return grade;
    }
    p("Swap1 created properly");
    grade+=inc;

    swap=execute("lsblk -n -b -o SIZE,FSTYPE,UUID /dev/vdb3").trim().replaceAll("\\s+", " ").split(" ");
    if(swap.length<3 || !swap[1].equals("swap")){
      p("Swap2 not created properly.1");
      return grade;
    }
    uuids.add(swap[2]);
    size=Long.parseLong(swap[0]);
    lower=(6*hundredmegs)-(hundredmegs/2);
    upper=(6*hundredmegs)+(hundredmegs/2);
    if(size<lower || size>upper){
        p("Swap2 not created properly.2");
        return grade;
    }
    p("Swap2 created properly");
    grade+=inc;

    swap=execute("lsblk -n -b -o SIZE,FSTYPE,UUID /dev/vdb4").trim().replaceAll("\\s+", " ").split(" ");
    if(swap.length<3 || !swap[1].equals("swap")){
      p("Swap3 not created properly.1");
      return grade;
    }
    uuids.add(swap[2]);
    size=Long.parseLong(swap[0]);
    lower=(8*hundredmegs)-(hundredmegs/2);
    upper=(8*hundredmegs)+(hundredmegs/2);
    if(size<lower || size>upper){
        p("Swap3 not created properly.2");
        return grade;
    }
    p("Swap3 created properly");
    grade+=inc;
    String fstab=FileUtils.readFileToString(new File("/etc/fstab"),"UTF-8");
    for(String uuid:uuids){
      if( !fstab.contains("UUID="+uuid)  ){
        p("Partition not mounted as required: "+uuid);
      }
      else{
        p("Partition mounted as required: "+uuid);
        grade+=(inc-1);
      }
    }
    return grade;
  }
  public float at()throws Exception{
    for(int i=0; i<100; i++){
      String content=execute("at -c "+i).toLowerCase();
      if(content.contains("echo") && content.contains(">") && 
        content.contains("winter") && content.contains("/tmp/winter_bashing.txt")){
          p("Single occurence job found");
          return 4f;
        }
    }
    p("Task 3.1 not satisfied");
    return 0;
  }

  public float selinux2()throws Exception{
    float grade=0f;
    float inc=2.5f;
    String k8s="/var/log/kubernetes";
    File file1= new File(k8s);
    if(!file1.exists()){
      System.out.println("No folder found:"+k8s);
      return 0f;
    }
    grade+=inc/2;
    String ocp="/var/log/openshift";
    File file2= new File(ocp);
    if(!file2.exists()){
      System.out.println("No folder found:"+ocp);
      return 0f;
    }
    grade+=inc/2;
    String context1=execute("ls -ldZ /var/log/kubernetes");
    String context2=execute("ls -ldZ /var/log/openshift");
    if(!context1.contains("openshift_log_t")){
      p("Wrong context found for /var/log/kubernetes:"+context1);
    }else{
      p("Right context found for "+k8s);
      grade+=inc;
    }
    if(!context2.contains("openshift_log_t")){
      p("Wrong context found for "+ocp+": "+context2);
    }else{
      p("Right context found for "+ocp);
      grade+=inc;
    }
    grade+=inc;
    return grade;
  }
   public float selinux1(){
    float grade=0f;
    String folder="/www/content";
    File file= new File(folder);
    if(!file.exists()){
      System.out.println("No folder found:"+folder);
      return 0f;
    }
    try{
    FileOutputStream fos= new FileOutputStream("/www/content/some.txt");
    String uuid=UUID.randomUUID().toString();
    fos.write(uuid.getBytes("UTF-8"));
    String urlString = "http://localhost/some.txt"; // Replace with your URL
            URL url = new URL(urlString);
            URLConnection connection = url.openConnection();
            BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder stringBuilder = new StringBuilder();
            String inputLine;
            while ((inputLine = br.readLine()) != null) {
                stringBuilder.append(inputLine);
            }
            br.close();
            String content = stringBuilder.toString();
            if(content.equals(uuid)){
                p("HTTPD Configured correctly");
                return 10f;
            }
    }catch(Exception e){
      p("HTTP not correctly configured");
      return 0f;
    }
    return 0f;
   }

  public float evaluateCronRedirection()throws Exception{
      String uuid=UUID.randomUUID().toString();
      execute("logger -p cron.info Message sent by grader script "+uuid);
     int i=0;
     String file="/log/cron";
     File f= new File(file);
     if(!f.exists()){
	p("File not found: "+file);
	return 0f;
     }
     while(i<20){
        String fileContent=FileUtils.readFileToString(new File(file), "UTF-8");
        i++;
        if(fileContent.contains(uuid)){
               System.out.println("Test content found in:"+file);
                return 10f;
        }
        System.out.println("Test content not found in:"+file+". Retrying ...");
        Thread.sleep(1000);
     }
     return 0;
    }

   @Override
    public void run(){
     try{
       PrintStream fileOut = new PrintStream(new FileOutputStream("output.txt"));
         System.setOut(fileOut);
         float total=0;
         String archives[]= new String[]{"/tmp/etc.tar.gz","/tmp/etc.tar.bz2","/tmp/etc.tar.xz"};
         Integer[] sizes = new Integer[]{5071425,4296378,3732368};

         float archive=archiveExists(archives,sizes);
         total+=archive;
         p("Archive: "+archive);
	 float sl1=selinux1();
	 p("SeLinux task 1: "+sl1);
         total+=sl1;
         float sl2=selinux2();
	 p("SeLinux task 2: "+sl2);
         total+=sl2;

         float at=at();
	 p("Single occu job: "+at);
         total+=at;
         float crontab=cron();

	 p("Multipe occu job: "+crontab);
         total+=crontab;

         float tune=tuning();
	 p("Tuning: "+tune);
         total+=tune;
         float vol=volume();
	 p("Storage: "+vol);
         total+=vol;
         float redirection=evaluateCronRedirection();
         total+=redirection;
	 p("SeLinux task 3: "+redirection);
         System.out.println("Final grade:"+total);
		  generateSignedContent("./output.txt",getMacAddress());
      }catch(Exception e){
      e.printStackTrace();
    }
    }

}
