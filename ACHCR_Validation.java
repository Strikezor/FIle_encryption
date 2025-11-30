package com.nach.impl;

import java.io.BufferedWriter;     
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;

//import java.util.Timer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
//import org.apache.logging.log4j.ThreadContext;
import com.jcraft.jsch.SftpException;
import com.nach.Utils.ExtractProperties;
import com.nach.Utils.ReturnFileGenerator_seq;
import com.nach.Utils.SecurePathValidator;
import com.nach.main.ACH_CR_Main;


public class ACHCR_Validation {
	private static final Logger log = LogManager.getLogger(ACH_CR_Main.class);
	private static final SecurePathValidator SecurePath = new SecurePathValidator();
    private String pattern = "ddMMyyyy";
    private static final String DB_URL = ExtractProperties.getInstance().getExtractProperty("DB_URL");    
    private static final String USER =  ExtractProperties.getInstance().getExtractProperty("USER");
    private static final String PASS =  ExtractProperties.getInstance().getExtractProperty("PASS");
    //private static final String Timer_Delay = ExtractProperties.getInstance().getExtractProperty("Timer_Delay");
    //private static final String Timer_Period = ExtractProperties.getInstance().getExtractProperty("Timer_Period");
    private static final String Selection_Query = ExtractProperties.getInstance().getExtractProperty("Selection_Query");
    private static final String Update_Process = ExtractProperties.getInstance().getExtractProperty("Update_Process");
    private static final String Update_SQL = ExtractProperties.getInstance().getExtractProperty("Update_SQL");
    private static final String Header_Query = ExtractProperties.getInstance().getExtractProperty("Header_Query");
    private static final String Data_Query = ExtractProperties.getInstance().getExtractProperty("Data_Query");
    private static final String TOT_ITEMS = ExtractProperties.getInstance().getExtractProperty("TOT_ITEMS");
    private static final String COUNT_ROW = ExtractProperties.getInstance().getExtractProperty("COUNT_ROW");
    private static final String DATE_FORMAT = ExtractProperties.getInstance().getExtractProperty("DATE_FORMAT");
    private static final String processFileLocation = ExtractProperties.getInstance().getExtractProperty("processFileLocation");
    SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);

    public void processACHFiles() {
        String fileName = null;
        String settleDate = null;
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             PreparedStatement selectStmt = conn.prepareStatement(Selection_Query);
             ResultSet rs = selectStmt.executeQuery()) {
            if (rs.next()) {
                fileName = rs.getString("FILE_NAME");
                settleDate = rs.getString("SETTLEMENT_DATE");
                //ThreadContext.put("FILENAME", "FILENAME: " + fileName);
                //ThreadContext.put("SETTLLEDATE", "SETTLLEDATE: " + settleDate);
                log.info("Return file generation for file name: " + fileName + " and settlement date: " + settleDate + " started");

                try (PreparedStatement updateStmt = conn.prepareStatement(Update_Process)) {
                    updateStmt.setString(1, sdf.format(new Date()));
                    updateStmt.setString(2, fileName);
                    updateStmt.setString(3, settleDate);
                    updateStmt.executeUpdate();
                    log.info("ACHFile process initiated");
                    if(SecurePath.validateFilePath(processFileLocation)) {
                    	writeACHFile(fileName, settleDate);
                    } else {
                    	log.error("Path are not valid");
                    }
                }
            } else {
                log.warn("No records found with FILE_STATUS = 21.");
            }

        }catch (IOException e) {
            log.error("IOException occurred while writing ACH file: ");
        } catch (SQLException e) {
            log.error("SQLException occurred while processing ACH file: " );
        } catch (NullPointerException e) {
            log.error("Null value encountered: " );
        } catch (Exception e) {
            log.error("An unexpected error occurred: ");
        } 
    }
    
    private void updateFileStatus(int status, String returnFileName, String Filename) throws SQLException {
    	
    	if(SecurePath.isValidFileName(returnFileName)&&SecurePath.isValidFileName(Filename)) {

	        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
	             PreparedStatement updateStmt = conn.prepareStatement(Update_SQL)) {
	            
	            updateStmt.setInt(1, status);
	            updateStmt.setString(2, sdf.format(new Date()));
	            updateStmt.setString(3, returnFileName);
	            updateStmt.setString(4, Filename); // Set the ID for the WHERE clause
	            
	            updateStmt.executeUpdate();
	            log.info("File status updated");
	        } catch (SQLException e) {
	            // Handle SQL exceptions
	        	log.error("SQLException in updating file status");
	            //e.printStackTrace();
	            throw e; // Rethrow the exception after logging
	        }
    	} else {
    		log.error("database can not be updated");
    	}
    }

    
    public void writeACHFile(String fileName1, String settleDate) throws IOException, SftpException, SQLException    {
    	log.info("Writing to the ACH_Return FILE generation");
        PreparedStatement dataStmt = null;
        ResultSet headerResult = null;
        ResultSet dataResult = null;

        try(Connection conn = DriverManager.getConnection(DB_URL, USER, PASS)) {
            

            // Directly use the provided fileName and settlementDate for processing
            String fileName = fileName1;                        
            String settlementDate = settleDate;
            String newReturnFile = generateDynamicFileName();
            String returnFileName= getFileName(newReturnFile);
            //String processFileLocation ="/home/aadeshapp/Process_Files_CR";
//            String processFileLocation ="E:\\\\ADESH\\\\ACH_CR\\\\Process_Files_CR";
            File source=new File(newReturnFile);
            //File dest=new File(processFileLocation);
            // Validate row count before proceeding
            Path path = Paths.get(processFileLocation);
            if (!Files.exists(path)) {
                Files.createDirectory(path);
            }
            if (validateRowCount(conn, fileName, settlementDate) && newReturnFile!=null) {
                // Proceed to write the file using the provided fileName and settlementDate
            	log.info("Row counts are same as total no. of rows");
                try (BufferedWriter writer = new BufferedWriter(new FileWriter(newReturnFile)); 
                	PreparedStatement headerStmt = conn.prepareStatement(Header_Query)){
                    headerStmt.setString(1, fileName);
                    headerStmt.setString(2, settlementDate);
                    headerResult = headerStmt.executeQuery();

                    if (headerResult.next()) {
                        String headerLine = createHeaderLine(headerResult);
                        writer.write(headerLine);
                        writer.newLine();
                        log.info("Header line generated in the file");
                    } else {
                    	log.info("No value in header");
                    }
                    dataStmt = conn.prepareStatement(Data_Query);
                    dataStmt.setString(1, fileName);
                    dataStmt.setString(2, settlementDate);
                    dataResult = dataStmt.executeQuery();

                    // Write each data row to the file
                    while (dataResult.next()) {
                        String dataLine = createDataLine(dataResult);
                        writer.write(dataLine);
                        writer.newLine();
                    }
                    writer.close();
                    log.info("All Data files generated");
                    log.info("ACH file written successfully to " + newReturnFile);
                    
                    if(copyReturnFile(source, processFileLocation)){
                    	updateFileStatus(23, returnFileName, fileName);  
                    } else {
                    	updateFileStatus(24, null, fileName);
                    }
                    
                } catch (IOException e) {
                	log.error("IO Exception in WriteACHFiles");
                	 updateFileStatus(24, null, fileName);
                	boolean b=source.delete();
                	if(b==true) {
                		log.info("Source File has been deleted");
                	} else {
                		log.info("Source file has not been deleted");
                	}
//                	dest.delete();
                    //e.printStackTrace();
                }
            } else {
                log.info("The file contents are invalid. The number of rows does not match.");
                updateFileStatus(24, null, fileName);
            }
           
        } catch (SQLException e) {
        	updateFileStatus(24, null, fileName1);
        	log.error("SQLEXception in WRITE_ACH FILES");
        	//source.delete();
            //e.printStackTrace();
        } finally {
            try {
                if (headerResult != null) headerResult.close();
                if (dataResult != null) dataResult.close();
                if (dataStmt != null) dataStmt.close();
            } catch (SQLException e) {
            	log.error("SQL EXception in closing the connections in writeACHFiles");
            }
        }
    } 
   
    private boolean copyReturnFile(File source, String destinationDir) throws SftpException {
    		log.info("Uploading final file in Encryption source folder started");
    		if (!source.exists() || !source.isFile()) {
    	        return false; // Source file doesn't exist or is not a file
    	    }

    	    File destFolder = new File(destinationDir);
    	    if (!destFolder.exists()) {
    	        // Try to create destination directory if it doesn't exist
    	        if (!destFolder.mkdirs()) {
    	            return false; // Failed to create destination directory
    	        }
    	    }

    	    File destFile = new File(destFolder, source.getName());

    	    try {
    	        Files.copy(source.toPath(), destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    	        log.info("file copy successfully");
    	        if(source.delete()) {
		        	log.info("Source File deleted successfully");
		        } else {
		        	log.error("Failed to delete the source file");
		        	return false;
		        }
    	        return true; // Copy successful
    	    } catch (IOException e) {
    	        log.info("file copy unsuccessfull");
    	        return false; // Copy failed due to an IOException
    	    }
    }

    private boolean validateRowCount(Connection conn, String file_Name , String Settlement_date) {
        try {
        //    String headerQuery = "SELECT TOT_NO_OF_ITEMS FROM ACHHEADER WHERE FILE_NAME ='ACH-CR-SBIN-13092021-TPZ000106691-INW' AND SETTLEMENT_DATE='13092021'";
            //String headerQuery = "SELECT TOT_NO_OF_ITEMS FROM ACHHEADER WHERE FILE_NAME = ? AND SETTLEMENT_DATE= ? ";
            PreparedStatement headerStatement = conn.prepareStatement(TOT_ITEMS);
            headerStatement.setString(1, file_Name);
            headerStatement.setString(2, Settlement_date);
            ResultSet headerResult = headerStatement.executeQuery();

            if (headerResult.next()) {
                int totalNoOfItems = headerResult.getInt("TOT_NO_OF_ITEMS");

                //String dataQuery = "SELECT COUNT(*) AS ROW_COUNT FROM ACHFILE WHERE FILE_NAME = ? AND SETTLEMENT_DATE = ?";
                PreparedStatement dataStatement = conn.prepareStatement(COUNT_ROW);
                dataStatement.setString(1, file_Name);
                dataStatement.setString(2, Settlement_date);
                ResultSet dataResult = dataStatement.executeQuery();

                if (dataResult.next()) {
                    int rowCount = dataResult.getInt("ROW_COUNT");
                    return rowCount == totalNoOfItems;
                }
            }
        } catch (SQLException e) {
        	log.error("Exception in validating row count");
            //e.printStackTrace();
        }
        return false;
    }

    private String createHeaderLine(ResultSet rs) throws SQLException  {
    	//log.info("Header line start");
        StringBuilder header = new StringBuilder();
        header.append(String.format("%-2s", rs.getString("ACH_TRANSACTION_CODE").trim())); // ACH transaction code
        header.append(String.format("%-7s", (rs.getString("CONTROL1") == null) ? "       " : "")); // Control
    	//log.info("Header line start1");
        header.append(String.format("%-87s", "")); // Filler
        header.append(String.format("%-7s", (rs.getString("CONTROL_CHARACTER") == null) ? "       " : "")); // Control
        String tot_no_of_items1=rs.getString("TOT_NO_OF_ITEMS");
        String tot_no_of_items2 = String.format("%09d", Long.parseLong(tot_no_of_items1.trim()));
        header.append(String.format("%-9s", tot_no_of_items2)); // Total Number of Items
    	//log.info("Header line start2");
        String TOT_AMOUNT1=rs.getString("TOT_AMOUNT");
        String TOT_AMOUNT2 = String.format("%013d", Long.parseLong(TOT_AMOUNT1.trim()));
        header.append(String.format("%-13s",TOT_AMOUNT2)); // Total Amount
    	//log.info("Header line start3");
        header.append(String.format("%-8s", rs.getString("SETTLEMENT_DATE"))); // Settlement Date
        header.append(String.format("%-8s", (rs.getString("INW_GEN_DATE") == null) ? "        " : "")); // Inward Generation Date
        header.append(String.format("%-19s", "")); // Filler
        header.append(String.format("%-11s", rs.getString("DESTINATION_BANK").trim())); // Destination Bank IFSC
        header.append(String.format("%-2s", rs.getString("SETTLEMENT_CYCLE").trim())); // Settlement Cycle
    	//log.info("Header line start4");
        header.append(String.format("%-133s", "                                                                                                                                    .")); // Filler with dot
        return header.toString();
    }

    private String createDataLine(ResultSet rs) throws SQLException {
    	//log.info("Data line generated");
        String dateInString = new SimpleDateFormat(pattern).format(new Date());

        StringBuilder data = new StringBuilder();
        data.append(String.format("%-2s", rs.getString("ACH_TRANSACTION_CODE"))); // ACH Transaction Code
        data.append(String.format("%-9s", "")); // Control
        //log.info("Data line generated1");
        String DESTINATION_ACCOUNT_TYPE1=rs.getString("DESTINATION_ACCOUNT_TYPE");
        String DESTINATION_ACCOUNT_TYPE2=null;
        if(DESTINATION_ACCOUNT_TYPE1==null || DESTINATION_ACCOUNT_TYPE1.equals("")){
        	DESTINATION_ACCOUNT_TYPE2="00";
        } else {
        	DESTINATION_ACCOUNT_TYPE2=String.format("%02d", Integer.parseInt(DESTINATION_ACCOUNT_TYPE1.trim()));
        }
        data.append(String.format("%-2s", DESTINATION_ACCOUNT_TYPE2)); // Destination Account Type
        //log.info("Data line generated2");
        data.append(String.format("%-3s", (rs.getString("LEDGER_FOLIO_NUMBER") == null) ? "   " : rs.getString("LEDGER_FOLIO_NUMBER"))); // Ledger Folio Number
        data.append(String.format("%-15s", "")); // Spaces User defined return reason
        data.append(String.format("%-40s", rs.getString("BENEFICIARY_HOLDER_NAME"))); // Beneficiary Account Holder's Name
        data.append(String.format("%-8s", "")); // Control spaces
        data.append(String.format("%-8s", "")); // User defined return reason spaces
        data.append(String.format("%-20s", rs.getString("USER_NAME"))); // User Name / Narration
        data.append(String.format("%-13s", "")); // Control
        //log.info("Data line generated3");
        String AMOUNT1=rs.getString("AMOUNT");
        String AMOUNT2 = String.format("%013d", Long.parseLong(AMOUNT1.trim()));
        data.append(String.format("%-13s", AMOUNT2)); // Amount
        //log.info("Data line generated4");
        data.append(String.format("%-10s", rs.getString("ACH_SEQ_NO"))); // ACH Item Seq No.
        data.append(String.format("%-10s", rs.getString("CHECKSUM"))); // Checksum
        data.append(String.format("%-7s", "")); // Reserved (Filler)
        data.append(String.format("%-11s", rs.getString("DEST_BANK"))); // Destination Bank IFSC
//        String BENEFICIARY_BANK_ACCNO1=rs.getString("BENEFICIARY_ACNO_FILE");
//        String BENEFICIARY_BANK_ACCNO2=String.format("%-35s", BENEFICIARY_BANK_ACCNO1).replace(' ', '0');
        data.append(String.format("%-35s", rs.getString("BENEFICIARY_ACNO_FILE"))); // Beneficiary's Bank Account number
        data.append(String.format("%-11s", rs.getString("SPONSOR_BANK"))); // Sponsor Bank IFSC
        data.append(String.format("%-18s", rs.getString("USER_NUMBER"))); // User Number
        data.append(String.format("%-30s", rs.getString("TRANSACTION_REFERENCE"))); // Transaction Reference
        data.append(String.format("%-3s", rs.getString("PRODUCT_TYPE"))); // Product Type
        //log.info("Data line generated5");
        String BENEFICIARY_AADHAAR_NO1=rs.getString("BENEFICIARY_AADHAAR_NO");
        String BENEFICIARY_AADHAAR_NO2=String.format("%015d", Long.parseLong(BENEFICIARY_AADHAAR_NO1.trim()));
        data.append(String.format("%-15s", BENEFICIARY_AADHAAR_NO2)); // Beneficiary Aadhaar Number
        data.append(String.format("%-20s", rs.getString("UMRN"))); // UMRN
        data.append(String.format("%-1s", (rs.getString("FLAG")==null)?" ":rs.getString("FLAG"))); // Flag for success / return
        data.append(String.format("%-2s", rs.getString("REASON_CODE"))); // Reason Code
        if(rs.getString("REASON_CODE").equals("00")){
        	data.append(String.format("%-8s", dateInString)); // Processed date
        } else {
        	data.append(String.format("%-8s", ""));
        }
        //log.info("Data line generated6");
        return data.toString();
    }

    // Method to generate the file name dynamically from ReturnFileGenerator_seq
    private String generateDynamicFileName() throws IOException {
        return ReturnFileGenerator_seq.generateReturnFile();
    }
    
    public static String getFileName(String filePath) {
        File file = new File(filePath);
        return file.getName(); // Return the file name
    }
    
    
}
