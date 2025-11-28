package com.tcs.sbi.launcher;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.Security;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;

import com.tcs.sbi.constants.ACHConstants;
import com.tcs.sbi.constants.ErrrorConstants;
import com.tcs.sbi.dbConnection.ACH_Manager;
import com.tcs.sbi.dbConnection.ConnectionManager;
import com.tcs.sbi.main.ACHEncryptionMain;
import com.tcs.sbi.util.ACHEncryptionProperties;
import com.tcs.sbi.util.ACHEncryptionUtility;

public class ACHEncryptionLuncher {

	private static final Logger log = LogManager.getLogger(ACHEncryptionLuncher.class);

	// Paths and Configs
	private static String sourcePath;
	private static String encryptedBackupPath;
	private static String originalFileBackupPath;
	private static String loggerPath;
	private static String ALLOWED_CHARS;
	
	// Key Paths (Properties)
	private static String privCerPath; // Path to chetan.pfx
	private static String NPCICertPath; // Path to npci.cer
	private static String certPass;    // Password for pfx

	// Loaded PGP Keys
	private static PGPPrivateKey pgpPrivKey; // Sender Private Key
	private static PGPPublicKey channelpgpPubkey; // NPCI Public Key

	private static int threadSleepTime;
	
	// Validation & Error Paths
	private static String duplicateFile;
	private static String txtvalidationFile;
	private static String fileNameValidationFile;
	private static String SignGenerationFailed; // Re-purposed for general failure
	private static String FileReadingFailed;
	private static String EncryptionProcessFailed;

	// SFTP
	private static String sftpHost, sftpUsername, sftpPwd, sftpPort;
	private static String remoteDir, archiveDir, localDir;
	private static int sftpwaitTime;

	// File Naming Config
	private static String crfilenamestart, crfileNameends;
	private static String drfileNameStart, drfileNameEnd;

	// Output Paths
	private static String crdestfilepath;
	private static String drdestfilepath;
	private static String orgndestpathcr;
	private static String orgndestpathdr;
	private static String destinationFilePath;

	// DB Config
	private static String dbUser, dbPwd, dbUrl;
	private static int minConn, maxConn, partitionCount, idleMaxAge, idleAgeTestTime;
	
	// Encryption Secrets
	private static String IV, Key;

	// Getters
	public static String getSourcePath() { return sourcePath; }
	public static String getDestinationFilePath() { return destinationFilePath; }
	public static PGPPublicKey getChannelpgpPubkey() { return channelpgpPubkey; }
	public static PGPPrivateKey getPgpPrivKey() { return pgpPrivKey; }
	public static String getEncryptedBackupPath() { return encryptedBackupPath; }
	public static String getCrdestfilepath() { return crdestfilepath; }
	public static String getDrdestfilepath() { return drdestfilepath; }
	public static String getOrgndestpathcr() { return orgndestpathcr; }
	public static String getOrgndestpathdr() { return orgndestpathdr; }
	public static String getOriginalFileBackupPath() { return originalFileBackupPath; }
	public static String getEncryptionProcessFailed() { return EncryptionProcessFailed; }
	public static String getDuplicateFile() { return duplicateFile; }
	public static String getALLOWED_CHARS() { return ALLOWED_CHARS; }

	static {
		try {
			// Load Properties
			loggerPath = ACHEncryptionProperties.getInstance().getProperty(ACHConstants.LOGGER_FILEPATH.toString());
			Configurator.initialize(null, loggerPath + ACHConstants.LOGGER_FILENAME.toString() + ".properties");
			
			sourcePath = ACHEncryptionProperties.getInstance().getProperty("SOURCE_PATH");
			encryptedBackupPath = ACHEncryptionProperties.getInstance().getProperty("DESTINATION_FILES_BACKUP_PATH");
			originalFileBackupPath = ACHEncryptionProperties.getInstance().getProperty("ORIGINAL_FILES_BACKUP_PATH");
			ALLOWED_CHARS = ACHEncryptionProperties.getInstance().getProperty("ALLOWED_CHARS");
			
			// Keys Config
			privCerPath = ACHEncryptionProperties.getInstance().getProperty("PRIV_CERT_PATH"); // Points to PFX
			NPCICertPath = ACHEncryptionProperties.getInstance().getProperty("NPCI_CERT_PATH"); // Points to CER
			certPass = ACHEncryptionProperties.getInstance().getProperty("CERT_PASSWORD");

			threadSleepTime = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("Thread_Sleep_Time"));
			
			duplicateFile = ACHEncryptionProperties.getInstance().getProperty("DUPLICATE_FILE_PATH");
			txtvalidationFile = ACHEncryptionProperties.getInstance().getProperty("TXT_VALIDATION_FAILED_PATH");
			fileNameValidationFile = ACHEncryptionProperties.getInstance().getProperty("FILETYPE_VALIDATION_FAILED_PATH");
			SignGenerationFailed = ACHEncryptionProperties.getInstance().getProperty("SIGN_GENERATION_FAILED_PATH");
			EncryptionProcessFailed = ACHEncryptionProperties.getInstance().getProperty("ENCRYPTION_PROCESS_FAILED_PATH");
			FileReadingFailed = ACHEncryptionProperties.getInstance().getProperty("FILE_READING_FAILED_PATH");
			
			sftpHost = ACHEncryptionProperties.getInstance().getProperty("SFTP_HOST");
			sftpUsername = ACHEncryptionProperties.getInstance().getProperty("SFTP_USERNAME");
			sftpPort = ACHEncryptionProperties.getInstance().getProperty("SFTP_PORT");
			sftpPwd = ACHEncryptionProperties.getInstance().getProperty("SFTP_PASSWORD");
			remoteDir = ACHEncryptionProperties.getInstance().getProperty("REMOTE_DIR");
			localDir = ACHEncryptionProperties.getInstance().getProperty("LOCAL_DIR");
			archiveDir = ACHEncryptionProperties.getInstance().getProperty("ARCHIVE_DIR");
			
			dbUser = ACHEncryptionProperties.getInstance().getProperty("dbuser");
			dbUrl = ACHEncryptionProperties.getInstance().getProperty("dburl");
			dbPwd = ACHEncryptionProperties.getInstance().getProperty("dbpwd");
			minConn = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("minConn"));
			maxConn = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("maxConn"));
			partitionCount = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("partitionCount"));
			idleMaxAge = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("idleMaxAge"));
			idleAgeTestTime = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("idleAgeTestTime"));
			
			IV = ACHEncryptionProperties.getInstance().getProperty("IV");
			Key = ACHEncryptionProperties.getInstance().getProperty("Key");
			
			sftpwaitTime = Integer.parseInt(ACHEncryptionProperties.getInstance().getProperty("SFTP_WAIT_TIME"));
			destinationFilePath = ACHEncryptionProperties.getInstance().getProperty("DESTINATION_FILE_PATH");
			
			crfilenamestart = ACHEncryptionProperties.getInstance().getProperty("CR_FILENAME_START_WITH");
			crfileNameends = ACHEncryptionProperties.getInstance().getProperty("CR_FILENAME_ENDS_WITH");
			drfileNameStart = ACHEncryptionProperties.getInstance().getProperty("DR_FILENAME_START_WITH");
			drfileNameEnd = ACHEncryptionProperties.getInstance().getProperty("DR_FILENAME_ENDS_WITH");
			
			crdestfilepath = ACHEncryptionProperties.getInstance().getProperty("CR_OUTPUTFILEPATH");
			drdestfilepath = ACHEncryptionProperties.getInstance().getProperty("DR_OUTPUTFILEPATH");
			orgndestpathcr = ACHEncryptionProperties.getInstance().getProperty("ORGN_OUTPUT_CR_PATH");
			orgndestpathdr = ACHEncryptionProperties.getInstance().getProperty("ORGN_OUTPUT_DR_PATH");

			// --- NEW KEY LOADING LOGIC ---
			Security.addProvider(new BouncyCastleProvider());

			// 1. Load NPCI Public Key (from .cer)
			String npciCertPathRaw = ACHEncryptionUtility.aesDecrypt(Key, IV, NPCICertPath);
			channelpgpPubkey = ACHEncryptionUtility.getPGPPublicKeyFromCer(npciCertPathRaw);
			log.info("Loaded NPCI Public Key from: " + npciCertPathRaw);

			// 2. Load MY Private Key (from .pfx)
			String myPfxPathRaw = ACHEncryptionUtility.aesDecrypt(Key, IV, privCerPath);
			String pfxPassword = ACHEncryptionUtility.aesDecrypt(Key, IV, certPass);
			pgpPrivKey = ACHEncryptionUtility.getPGPPrivateKeyFromPFX(myPfxPathRaw, pfxPassword);
			log.info("Loaded Sender Private Key from: " + myPfxPathRaw);

			ConnectionManager.configureConnPool();

		} catch (Exception e) {
			log.error("Initialization Failed: ", e);
		}
	}

	public static void main(String[] args) {
		log.info("********** || AADESH_ACH_CR_DR_ENC UTILITY STARTED || **********");
		while (true) {
			try {
				HashMap<String, Object> decdmap = new HashMap<String, Object>();
				String referenceNumber = "";
				File Filelist = new File(sourcePath);
				File[] listOfFiles = Filelist.listFiles();

				// Date Calculation Logic
				Calendar cal = Calendar.getInstance();
				int calMonth = cal.get(Calendar.MONTH) + 1;
				int calYear = cal.get(Calendar.YEAR);
				int calDate = cal.get(Calendar.DATE);
				String currMonth = (calMonth < 10) ? "0" + calMonth : "" + calMonth;
				String currentDate = (calDate < 10) ? "0" + calDate : "" + calDate;

				if (listOfFiles != null && listOfFiles.length > 0) {
					ArrayList<String> nameOFFiles = new ArrayList<String>();
					for (File files : listOfFiles) {
						String fileName = files.getName();
						referenceNumber = ACHEncryptionUtility.generateRefrenceNumber();
						decdmap.put("FileName", fileName);
						decdmap.put("fileCopiedTime", ACHEncryptionUtility.getTimestamp());
						decdmap.put("RefrenceNumber", referenceNumber);
						decdmap.put("FileType", fileName.contains("-CR-") ? ErrrorConstants.CR_FILE_TYPE.toString() : ErrrorConstants.DR_FILE_TYPE.toString());

						boolean isfileprocessed = ACH_Manager.isFilepreviouslyProcessed(fileName, new Date());

						if (!isfileprocessed) {
							if (ACHEncryptionUtility.extensionValidation(fileName)) {
								// Name Validation
								if ((fileName.contains(crfilenamestart + currentDate + currMonth + calYear) && fileName.contains(crfileNameends))
								 || (fileName.contains(drfileNameStart + currentDate + currMonth + calYear) && fileName.contains(drfileNameEnd))) {
									nameOFFiles.add(fileName);
								} else {
									// Invalid Name
									handleValidationFailure(files, decdmap, referenceNumber, fileNameValidationFile, currentDate, currMonth, calYear, ErrrorConstants.ER001);
								}
							} else {
								// Invalid Extension
								handleValidationFailure(files, decdmap, referenceNumber, txtvalidationFile, currentDate, currMonth, calYear, ErrrorConstants.ER002);
							}
						} else {
							// Duplicate
							log.info("File already processed: " + fileName);
							Files.move(Paths.get(sourcePath + File.separator + fileName),
									Paths.get(duplicateFile + File.separator + fileName), StandardCopyOption.REPLACE_EXISTING);
						}
					}
					
					// Process Valid Files
					if (nameOFFiles.size() > 0) {
						log.info("Files to process: " + nameOFFiles.size());
						ExecutorService eService = Executors.newSingleThreadExecutor();
						Runnable worker = new ACHEncryptionMain(nameOFFiles, sourcePath, "");
						eService.execute(worker);
						eService.shutdown();
						while (!eService.isTerminated()) { }
					}
				} else {
					log.info("No files found. Sleeping for " + threadSleepTime);
					Thread.sleep(threadSleepTime);
				}
			} catch (Exception e) {
				log.error("Exception in launcher loop", e);
			}
		}
	}
	
	private static void handleValidationFailure(File file, HashMap<String, Object> map, String ref, String destPath, String date, String month, int year, ErrrorConstants code) throws Exception {
		map.put("Status", ErrrorConstants.VALIDATION_FAILED.toString());
		map.put("lastUpdatedtime", ACHEncryptionUtility.getTimestamp());
		map.put("ERROR_CODE", code.name());
		
		File destDir = new File(destPath + date + month + year);
		if (!destDir.exists()) destDir.mkdirs();
		
		Files.move(file.toPath(), Paths.get(destDir + File.separator + file.getName()), StandardCopyOption.REPLACE_EXISTING);
		ACH_Manager.insertintoAch_CR_logs(map, new Date());
		log.info("Validation Failed for: " + file.getName() + " Moved to: " + destDir);
	}
}
