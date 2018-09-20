/**
 * @author Ishaan Thakker
 * Program to parse and extract information from packets of type TCP, UDP, ICMP 
 * and UDP IPV4
 */
import java.io.*;
import java.io.IOException;

public class wirebug {

    
    public static void main(String[] args) throws FileNotFoundException, IOException {
        
		if(args.length<1){
			System.out.println("Please enter a file name");
			System.exit(0);
		}
		String filename = args[0];
		
		try{
			File f = new File(filename);
        
        FileInputStream input  = new FileInputStream(f);
        
        int content = 0;
        int linecount=0;
        int counter = 0;
        
        String s = "";
        String temp = "";
        String t;
        
        while((content = input.read())!=-1){
            
             t = Integer.toHexString(content);
            if(t.length()==1){
                temp = "0"+t;
                t = temp;
                
            }
            s+= t;
            counter++;
            if(counter==2){
                s+=" ";
                counter=0;
            }
            linecount++;
            if(linecount==16){
                linecount=0;
                s+="\n";
            }
        }
        
        System.out.println(s);
        String[] tt = s.split("\n");
        System.out.println();
        
        String line3[] = tt[2].split(" ");
        String line4[] = tt[3].split(" ");
        String line5[] = tt[4].split(" ");
        String line6[] = tt[5].split(" ");
        
        String ipversion = line4[2];
        
        String protocol="";
        
        if(line4[7].substring(2,4).equals("06")){
            protocol="6 TCP";
            printTCP(s);
        }else if(line4[7].substring(2,4).equals("11")){
            protocol="11 UDP";
            printUDP(s);
        }
        else if(line4[7].substring(2,4).equals("01")){
            protocol="ICMP ";
            printICMP(s);
            }
			
		}catch(java.io.FileNotFoundException io){
			System.out.println("File is not Found please enter a valid file name");
		}
		catch(Exception e){
			System.out.println(e.getMessage());
		}
        
        
    }
    /**
     * Function to get the size of the packet
     * @param s is the string with the packet 
     * @return size of the packet
     */
    static int printsize(String s){
         
          s = s.replaceAll(" ", "");
         
          String[] lines = s.split("\n");
          int count = 0;
          for(String line: lines){
              count+=line.length();
          }
          count = count/2;
          return (count-40);
    }
    /**
     * Function to get the flags in binary format
     * @param x is the hexstring of the flag
     * @return binary format of the flag in 9 digits
     */
    static String getflag(String x){
    
        x = Long.toBinaryString(Long.parseLong(x,16));
        
        String s = "";
        int ind=0;
        if(x.length()<9){
            for(int i=0;i<9-x.length();i++){
                s+="0";
            }
            for(int i=s.length();i<9;i++){
                s+=x.charAt(ind);
                ind++;
            }
        }
        return s;
        
    }
    /**
     * 
     * @param s is the String which containts the Ethernet Header, IP header and ICMP Header
     */
    static void printICMP(String s){
		System.out.println("*****************************************");
        System.out.println("***                                   ***");
        System.out.println("***         ICMP PACKET FOUND         ***");
        System.out.println("***                                   ***");
        System.out.println("*****************************************");
         String[] tt = s.split("\n");
        
        String line3[] = tt[2].split(" ");
        String line4[] = tt[3].split(" ");
        String line5[] = tt[4].split(" ");
        String line6[] = tt[5].split(" ");
        
        
      
       
        String ethernet_dest = line3[4].substring(0,2)+":"+line3[4].substring(2,4)
                +":"+line3[5].substring(0,2)+":"+line3[5].substring(2,4)
                +":"+line3[6].substring(0,2)+":"+line3[6].substring(2,4);
        
        String ethernet_source = line3[7].substring(0,2)+":"+line3[7].substring(2,4)
                +":"+line4[0].substring(0,2)+":"+line4[0].substring(2,4)
                +":"+line4[1].substring(0,2)+":"+line4[1].substring(2,4);
        
        String ether_type = line4[2];
        
        String version = line4[3].substring(0,1);
        int header_length = Integer.parseInt(line4[3].substring(1,2))*4;
        String servicetype = "0x"+line4[3].substring(2,4);
        long total_length2 = Long.parseLong(line4[4],16);
        long identification = Long.parseLong(line4[5],16);
        String flags = "0x"+line4[6];
        long time_to_live = Long.parseLong(line4[7].substring(0,2),16);
        String protocol="";
        if(line4[7].substring(2,4).equals("06")){
            protocol="6 TCP";
        }else if(line4[7].substring(2,4).equals("01")){
             protocol="ICMP";
        }
        
        String headerchecksum = line5[0];
        String ipheader_source = Long.parseLong(line5[1].substring(0,2),16)+"."+
               Long.parseLong(line5[1].substring(2,4),16)+"."+
                Long.parseLong(line5[2].substring(0,2),16)+"."+
                Long.parseLong(line5[2].substring(2,4),16);
        String ipheader_dest = Long.parseLong(line5[3].substring(0,2),16)+"."+
               Long.parseLong(line5[3].substring(2,4),16)+"."+
                Long.parseLong(line5[4].substring(0,2),16)+"."+
                Long.parseLong(line5[4].substring(2,4),16);     
        
        long type = Long.parseLong(line5[5].substring(0,2));
        long code = Long.parseLong(line5[5].substring(2,4));
        String icmp_checksum = line5[6];
        String identifier_be = Long.toString(Long.parseLong(line5[7],16));
        String x = line5[7].substring(2,4)+line5[7].substring(0,2);
        String identifier_le = Long.toString(Long.parseLong(x,16));
        String seq_no_be = Long.toString(Long.parseLong(line6[0],16));
        x = line6[0].substring(2,4)+line6[0].substring(0,2);
        String seq_no_le = Long.toString(Long.parseLong(x,16));
        
        System.out.println("******Ethernet Header*******");
        System.out.println("Destination: "+ethernet_dest);
        System.out.println("Source: "+ethernet_source);
        System.out.println("EtherType:"+ether_type);
        System.out.println("Packet Size: "+printsize(s));
        System.out.println();System.out.println();
        
        System.out.println("*********IP Header**********");
        System.out.println();
        System.out.println("Version: "+version);
        System.out.println("Header length: "+header_length+" bytes");
        System.out.println("Type of service: "+servicetype);
        System.out.println("Total_length: "+total_length2+" bytes");
        System.out.println("Identification: "+identification);
        System.out.println("Flags: "+flags);
        
        String flagbit = flags.substring(2,3);
        String bin = Integer.toBinaryString(Integer.parseInt(flagbit));
    
        String binary = "";
        for(int i=0;i<4-bin.length();i++){
            binary+="0";
        }
        int ind = 0;
        
        for(int i = 4-bin.length()-1;i<3;i++){
            binary+=bin.charAt(ind);
            ind++;
        }
        
        String flags1 = binary.substring(0,1);
        String flags2 = binary.substring(1,2);
        String flags3 = binary.substring(2,3);
        String flags4 = binary.substring(3,4);
       
        if(flags1.equals("0")){
            System.out.println("0... .... .... .... = Reserved Bit: Not Set");
        }else{
            System.out.println("1... .... .... .... = Reserved Bit: Set");
        }
        
        if(flags2.equals("0")){
            System.out.println(".0.. .... .... .... = Don't Fragment: Not Set");
        }else{
            System.out.println(".1.. .... .... .... = Don't Fragment: Set");
        }
        
        if(flags3.equals("0")){
            System.out.println("..0. .... .... .... = More Fragments: Not Set");
        }else{
            System.out.println("..1. .... .... .... = More Fragments: Set");
        }
        
        if(flags4.equals("0")){
            System.out.println("...0 0000 0000 0000 = Reserved Bit: Not Set");
        }else{
            System.out.println("...1 0000 0000 0000 = Reserved Bit: Set");
        }
        
        
        
        System.out.println("Time to Live: "+time_to_live);
        System.out.println("Protocol: "+protocol);
        System.out.println("Header checksum: "+headerchecksum);
        System.out.println("Source: "+ipheader_source);
        System.out.println("Destination: "+ipheader_dest);
        
        System.out.println();System.out.println();
        System.out.println("*******ICMP Header*********");
        System.out.println("Type: "+type);
        System.out.println("Code: "+code);
        System.out.println("Checksum: 0x"+icmp_checksum);
        System.out.println("Identifier (BE): "+identifier_be);
        System.out.println("Identifier (LE): "+identifier_le);
        System.out.println("Sequence No(BE): "+seq_no_be);
        System.out.println("Sequence No(LE): "+seq_no_le);
    }
    
    /**
     * 
     * @param s is the String which containts the Ethernet Header, IP header and UDPV6 Header
     */
    /**
     * 
     * @param s is the String which contains the Ethernet Header, IP header and UDP Header
     */
    static void printUDP(String s){
        System.out.println("*****************************************");
        System.out.println("***                                   ***");
        System.out.println("***         UDP PACKET FOUND          ***");
        System.out.println("***                                   ***");
        System.out.println("*****************************************");
        String[] tt = s.split("\n");
        System.out.println();
        
        String line3[] = tt[2].split(" ");
        String line4[] = tt[3].split(" ");
        String line5[] = tt[4].split(" ");
        String line6[] = tt[5].split(" ");
        
        
        String ethernet_dest = line3[4].substring(0,2)+":"+line3[4].substring(2,4)
                +":"+line3[5].substring(0,2)+":"+line3[5].substring(2,4)
                +":"+line3[6].substring(0,2)+":"+line3[6].substring(2,4);
        
        String ethernet_source = line3[7].substring(0,2)+":"+line3[7].substring(2,4)
                +":"+line4[0].substring(0,2)+":"+line4[0].substring(2,4)
                +":"+line4[1].substring(0,2)+":"+line4[1].substring(2,4);
        
        String ether_type = line4[2];
        
        String version = line4[3].substring(0,1);
        int header_length = Integer.parseInt(line4[3].substring(1,2))*4;
        String servicetype = "0x"+line4[3].substring(2,4);
        long total_length2 = Long.parseLong(line4[4],16);
        long identification = Long.parseLong(line4[5],16);
        String flags = "0x"+line4[6];
        long time_to_live = Long.parseLong(line4[7].substring(0,2),16);
        String protocol="";
        if(line4[7].substring(2,4).equals("06")){
            protocol="6 TCP";
        }
        
        String headerchecksum = line5[0];
        String ipheader_source = Long.parseLong(line5[1].substring(0,2),16)+"."+
               Long.parseLong(line5[1].substring(2,4),16)+"."+
                Long.parseLong(line5[2].substring(0,2),16)+"."+
                Long.parseLong(line5[2].substring(2,4),16);
        String ipheader_dest = Long.parseLong(line5[3].substring(0,2),16)+"."+
               Long.parseLong(line5[3].substring(2,4),16)+"."+
                Long.parseLong(line5[4].substring(0,2),16)+"."+
                Long.parseLong(line5[4].substring(2,4),16);     
                
        long sourceport = Long.parseLong(line5[5],16);
        long destport = Long.parseLong(line5[6],16);
        long window = Long.parseLong(line6[4],16);
        String tcpchecksum = "0x"+line6[5];
        //int urgentpointer = Integer.parseInt(line6[6]);
        long udplength = Long.parseLong(line5[7],16);
        String udpchecksum = line6[0];
        
        System.out.println("******Ethernet Header*******");
        System.out.println("Destination: "+ethernet_dest);
        System.out.println("Source: "+ethernet_source);
        System.out.println("EtherType:"+ether_type);
        System.out.println("Packet Size: "+printsize(s));
        System.out.println();System.out.println();
        
        System.out.println("*********IP Header**********");
        System.out.println();
        System.out.println("Version: "+version);
        System.out.println("Header length: "+header_length+" bytes");
        System.out.println("Type of service: "+servicetype);
		
        System.out.println("Total_length: "+total_length2+" bytes");
        System.out.println("Identification: "+identification);
        System.out.println("Flags: "+flags);
        
        String flagbit = flags.substring(2,3);
        String bin = Integer.toBinaryString(Integer.parseInt(flagbit));
    
        String binary = "";
        for(int i=0;i<4-bin.length();i++){
            binary+="0";
        }
        int ind = 0;
        
        for(int i = 4-bin.length()-1;i<3;i++){
            binary+=bin.charAt(ind);
            ind++;
        }
        
        String flags1 = binary.substring(0,1);
        String flags2 = binary.substring(1,2);
        String flags3 = binary.substring(2,3);
        String flags4 = binary.substring(3,4);
       
        if(flags1.equals("0")){
            System.out.println("0... .... .... .... = Reserved Bit: Not Set");
        }else{
            System.out.println("1... .... .... .... = Reserved Bit: Set");
        }
        
        if(flags2.equals("0")){
            System.out.println(".0.. .... .... .... = Don't Fragment: Not Set");
        }else{
            System.out.println(".1.. .... .... .... = Don't Fragment: Set");
        }
        
        if(flags3.equals("0")){
            System.out.println("..0. .... .... .... = More Fragments: Not Set");
        }else{
            System.out.println("..1. .... .... .... = More Fragments: Set");
        }
        
        if(flags4.equals("0")){
            System.out.println("...0 0000 0000 0000 = Reserved Bit: Not Set");
        }else{
            System.out.println("...1 0000 0000 0000 = Reserved Bit: Set");
        }
        
        System.out.println("Time to Live: "+time_to_live);
        System.out.println("Protocol: UDP");
        System.out.println("Header checksum: "+headerchecksum);
        System.out.println("Source: "+ipheader_source);
        System.out.println("Destination: "+ipheader_dest);
        
        System.out.println();System.out.println();
        System.out.println("*******UDP Header*********");
        System.out.println("Source port: "+sourceport);
        System.out.println("Destination port: "+destport);
        System.out.println("UDP Length: "+udplength);
        System.out.println("Check sum: 0x"+udpchecksum);
        
    }
    /**
     * 
     * @param s is the String which containts the Ethernet Header, IP header and TCP Header
     */
    static void printTCP(String s){
        System.out.println("*****************************************");
        System.out.println("*                                       *");
        System.out.println("*           TCP PACKET FOUND            *");
        System.out.println("*                                       *");
        System.out.println("*****************************************");
        String[] tt = s.split("\n");
        System.out.println();
        
        String line3[] = tt[2].split(" ");
        String line4[] = tt[3].split(" ");
        String line5[] = tt[4].split(" ");
        String line6[] = tt[5].split(" ");
        String protocol="";
        if(line4[7].substring(2,4).equals("06")){
            protocol="6 TCP";
            
        }else if(line4[7].substring(2,4).equals("11")){
            
        }
        
      
       
        String ethernet_dest = line3[4].substring(0,2)+":"+line3[4].substring(2,4)
                +":"+line3[5].substring(0,2)+":"+line3[5].substring(2,4)
                +":"+line3[6].substring(0,2)+":"+line3[6].substring(2,4);
        
        String ethernet_source = line3[7].substring(0,2)+":"+line3[7].substring(2,4)
                +":"+line4[0].substring(0,2)+":"+line4[0].substring(2,4)
                +":"+line4[1].substring(0,2)+":"+line4[1].substring(2,4);
        
        String ether_type = line4[2];
        
        String version = line4[3].substring(0,1);
        int header_length = Integer.parseInt(line4[3].substring(1,2))*4;
        String servicetype = "0x"+line4[3].substring(2,4);
        long total_length2 = Long.parseLong(line4[4],16);
        long identification = Long.parseLong(line4[5],16);
        String flags = "0x"+line4[6];
        long time_to_live = Long.parseLong(line4[7].substring(0,2),16);
        
        
        String headerchecksum = line5[0];
        String ipheader_source = Long.parseLong(line5[1].substring(0,2),16)+"."+
               Long.parseLong(line5[1].substring(2,4),16)+"."+
                Long.parseLong(line5[2].substring(0,2),16)+"."+
                Long.parseLong(line5[2].substring(2,4),16);
        String ipheader_dest = Long.parseLong(line5[3].substring(0,2),16)+"."+
               Long.parseLong(line5[3].substring(2,4),16)+"."+
                Long.parseLong(line5[4].substring(0,2),16)+"."+
                Long.parseLong(line5[4].substring(2,4),16);     
                
        long sourceport = Long.parseLong(line5[5],16);
        long destport = Long.parseLong(line5[6],16);
        long window = Long.parseLong(line6[4],16);
        String tcpchecksum = "0x"+line6[5];
        int urgentpointer = Integer.parseInt(line6[6]);
        
        long seqnum = Long.parseLong((line5[7]+line6[0]),16);
        long ack = Long.parseLong((line6[1]+line6[2]),16);
        
        System.out.println("******Ethernet Header*******");
        System.out.println("Destination: "+ethernet_dest);
        System.out.println("Source: "+ethernet_source);
        System.out.println("EtherType:"+ether_type);
        System.out.println("Packet Size: "+printsize(s));
        System.out.println();System.out.println();
        
        System.out.println("*********IP Header**********");
        System.out.println();
        System.out.println("Version: "+version);
        System.out.println("Header length: "+header_length+" bytes");
        System.out.println("Type of service: "+servicetype);
        System.out.println("Total_length: "+total_length2+" bytes");
        System.out.println("Identification: "+identification);
        System.out.println("Flags: "+flags);
        String flagbit = flags.substring(2,3);
        String bin = Integer.toBinaryString(Integer.parseInt(flagbit));
    
        String binary = "";
        for(int i=0;i<4-bin.length();i++){
            binary+="0";
        }
        int ind = 0;
        
        for(int i = 4-bin.length()-1;i<3;i++){
            binary+=bin.charAt(ind);
            ind++;
        }
        
        String flags1 = binary.substring(0,1);
        String flags2 = binary.substring(1,2);
        String flags3 = binary.substring(2,3);
        String flags4 = binary.substring(3,4);
       
        if(flags1.equals("0")){
            System.out.println("0... .... .... .... = Reserved Bit: Not Set");
        }else{
            System.out.println("1... .... .... .... = Reserved Bit: Set");
        }
        
        if(flags2.equals("0")){
            System.out.println(".0.. .... .... .... = Don't Fragment: Not Set");
        }else{
            System.out.println(".1.. .... .... .... = Don't Fragment: Set");
        }
        
        if(flags3.equals("0")){
            System.out.println("..0. .... .... .... = More Fragments: Not Set");
        }else{
            System.out.println("..1. .... .... .... = More Fragments: Set");
        }
        
        if(flags4.equals("0")){
            System.out.println("...0 0000 0000 0000 = Reserved Bit: Not Set");
        }else{
            System.out.println("...1 0000 0000 0000 = Reserved Bit: Set");
        }
        
        System.out.println("Time to Live: "+time_to_live);
        System.out.println("Protocol: "+protocol);
        System.out.println("Header checksum: "+headerchecksum);
        System.out.println("Source: "+ipheader_source);
        System.out.println("Destination: "+ipheader_dest);
        
        System.out.println();System.out.println();
        System.out.println("*******TCP Header*********");
        System.out.println("Source port: "+sourceport);
        System.out.println("Destination port: "+destport);
        System.out.println("Window: "+window);
        System.out.println("Check sum: "+tcpchecksum);
        System.out.println("Urgent Pointer: "+urgentpointer);
        System.out.println("Sequence Number: "+seqnum);
        System.out.println("Acknowledge Number: "+ack);
        System.out.println("flag: 0x"+line6[3].substring(1,4));
        String flg = getflag(line6[3].substring(1,4));
        String middle = "";
        String zero_one = "";
        System.out.println("000. .... .... = Reserved: Not Set");
        for(int i=0;i<flg.length();i++){
            if(flg.charAt(i)=='0'){
                middle = "No ";
                zero_one = "0";
            }else{
                zero_one = "1";
                middle = "";
            }
            
            switch(i+1){
                case 1: System.out.println("..."+zero_one+" .... .... = "+middle+"Nonce"); break;
                case 2: System.out.println(".... "+zero_one+"... .... = "+middle+"CWR"); break;
                case 3: System.out.println(".... ."+zero_one+".. .... = "+middle+"ECN Echo"); break;
                case 4: System.out.println(".... .."+zero_one+". .... = "+middle+"Urgent"); break;
                case 5: System.out.println(".... ..."+zero_one+" .... = "+middle+"ACK"); break;
                case 6: System.out.println(".... .... "+zero_one+"... = "+middle+"Push"); break;
                case 7: System.out.println(".... .... ."+zero_one+".. = "+middle+"Reset"); break;
                case 8: System.out.println(".... .... .."+zero_one+". = "+middle+"Syn"); break;
                case 9: System.out.println(".... .... ..."+zero_one+" = "+middle+"Fin"); break;
            }
        }
    }
}
