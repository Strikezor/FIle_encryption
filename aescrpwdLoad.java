package com.tcs.bancs.microservices.configuration;

import java.io.UnsupportedEncodingException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.Step;
import org.springframework.batch.core.configuration.annotation.EnableBatchProcessing;
import org.springframework.batch.core.configuration.annotation.JobBuilderFactory;
import org.springframework.batch.core.configuration.annotation.StepBuilderFactory;
import org.springframework.batch.core.configuration.annotation.StepScope;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.batch.core.launch.support.RunIdIncrementer;
import org.springframework.batch.core.launch.support.SimpleJobLauncher;
import org.springframework.batch.core.partition.PartitionHandler;
import org.springframework.batch.core.partition.support.TaskExecutorPartitionHandler;
import org.springframework.batch.core.repository.JobRepository;
import org.springframework.batch.core.repository.support.JobRepositoryFactoryBean;
import org.springframework.batch.item.database.JdbcCursorItemReader;
import org.springframework.batch.item.database.JdbcPagingItemReader;
import org.springframework.batch.item.database.PagingQueryProvider;
import org.springframework.batch.item.database.builder.JdbcCursorItemReaderBuilder;
import org.springframework.batch.item.database.builder.JdbcPagingItemReaderBuilder;
import org.springframework.batch.item.database.support.SqlPagingQueryProviderFactoryBean;
import org.springframework.batch.item.file.FlatFileItemWriter;
import org.springframework.batch.item.file.transform.BeanWrapperFieldExtractor;
import org.springframework.batch.item.file.transform.DelimitedLineAggregator;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.batch.support.transaction.ResourcelessTransactionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.task.TaskExecutor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.web.client.HttpClientErrorException;

import com.tcs.bancs.microservices.Encryption.AESEncryptionUtility;
import com.tcs.bancs.microservices.achmModel.EncryptedGLReqBean;
import com.tcs.bancs.microservices.db.model.ACHMDUP;
import com.tcs.bancs.microservices.partitionar.RecourdCountPartitioner;
import com.tcs.bancs.microservices.processor.MRWritter;
import com.tcs.bancs.microservices.processor.MrProcessor;

@Configuration
@EnableBatchProcessing
public class MRLONDEPtranConfig {
	
	private static int chunksize;
	private static String url;
	private static String user;
	private static String pwd;
	private static String key;
	private static String iv;
	
	@SuppressWarnings("static-access")
	@Autowired
	public MRLONDEPtranConfig(@Value("${CHUNK_SIZE}") int chunksize,@Value("${dburl}") String url ,@Value("${dbuser}") String user ,@Value("${dbpwd}") String pwd,@Value("${Key}") String key,@Value("${IV}") String iv) {
		this.chunksize = chunksize;
		this.url = url;
		this.pwd = pwd;
		this.user = user;
		this.key=key;
		this.iv=iv;
	}
//	@Autowired
//	private DataSource dataSource;

	@Autowired
	StepBuilderFactory stepBuilderFactory;

	@Autowired
	JobBuilderFactory jobBuilderFactory;

	@Autowired
	MrProcessor achmLonDepProcessor;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private MRWritter mRResponceWritter;
	
	@Autowired
	private AESEncryptionUtility aesEncryptionUtility;

	String urlOG;
	String userName;
	String password;
	@Bean
	public DataSource dataSource() {
		
		try {
			urlOG = aesEncryptionUtility.aesDecrypt(key, iv, url);
			userName = aesEncryptionUtility.aesDecrypt(key, iv, user);
			password = aesEncryptionUtility.aesDecrypt(key, iv, pwd);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
        DataSourceBuilder dataSourceBuilder = DataSourceBuilder.create();
        dataSourceBuilder.url(urlOG);
        dataSourceBuilder.username(userName);
        dataSourceBuilder.password(password);
        return dataSourceBuilder.build();
    }

	@Bean
	public Job MRtranJob() throws Exception {

		return jobBuilderFactory.get("accountEnquiryService")
				.start(checkDataStep())
				.incrementer(new RunIdIncrementer())
				.next(accountEnquiryService())
				.build();
	}

	@Bean
	public Step accountEnquiryService() throws Exception {
		return stepBuilderFactory.get("accountEnquiryService")
				.partitioner("MRTranStep", new RecourdCountPartitioner(jdbcTemplate, dataSource()))
				.partitionHandler(partitionHandler()).build();
	}

	@Bean
	public Step MRTranStep() throws Exception {

		

		return stepBuilderFactory
				.get("MRTranStep")
				.<ACHMDUP, Map<String, String>>chunk(chunksize)
				.reader(pagingItemReader(null, null))
				.processor(achmLonDepProcessor)
				.writer(mRResponceWritter)
				.listener(mRResponceWritter)
				.faultTolerant()
				.skip(HttpClientErrorException.class)
				.skipLimit(100)
				.build();

	}


//	@StepScope
//	@Bean(destroyMethod = "")
//	public JdbcCursorItemReader<ACHMDUP> MRReader(@Value("#{stepExecutionContext['start']}") Integer start,
//			@Value("#{stepExecutionContext['end']}") Integer end) {
//		String sqlquery = "select FILE_NAME,ACHM_SOC_NO,ACHM_TRN_DATE,ACHM_SEQ_NO,ACHM_JRNL_NO,ACHM_ACCT_NO,ACHM_TXN_BRCH,ACHM_HOME_BRANCH,ACHM_USER_NAME,ACHM_AADHAR_NO,ACHM_UMRN_NO,ACHM_USER_NO,ACHM_TRAN_CODE,ACHM_AMOUNT,ACHM_SET_DATE,ACHM_SET_CYC,ACHM_ERROR_NO,ACHM_REMITTER_NAME,ACHM_PROD_CODE,ACHM_STATUS,ACHM_REQ_REF_NO from (SELECT FILE_NAME,ACHM_SOC_NO,ACHM_TRN_DATE,ACHM_SEQ_NO,ACHM_JRNL_NO,ACHM_ACCT_NO,ACHM_TXN_BRCH,ACHM_HOME_BRANCH,ACHM_USER_NAME,ACHM_AADHAR_NO,ACHM_UMRN_NO,ACHM_USER_NO,ACHM_TRAN_CODE,ACHM_AMOUNT,ACHM_SET_DATE,ACHM_SET_CYC,ACHM_ERROR_NO,ACHM_REMITTER_NAME,ACHM_PROD_CODE,ACHM_STATUS,ACHM_REQ_REF_NO,ROW_NUMBER() OVER (ORDER BY ACHM_REQ_REF_NO) AS row_num  FROM ACHM WHERE ACHM_STATUS='27') WHERE ROW_NUM BETWEEN ? and ?";
//
//		return new JdbcCursorItemReaderBuilder<ACHMDUP>().dataSource(dataSource).name("MRReader").sql(sqlquery)
//				.preparedStatementSetter((PreparedStatementSetter) new PreparedStatementSetter() {
//
//					@Override
//					public void setValues(PreparedStatement ps) throws SQLException {
//						ps.setInt(1, start);
//						ps.setInt(2, end);
//
//					}
//				}).rowMapper(new RowMapper<ACHMDUP>() {
//
//					@Override
//					public ACHMDUP mapRow(ResultSet rs, int rowNum) throws SQLException {
//						ACHMDUP s = new ACHMDUP();
//						s.setFILE_NAME(rs.getString("FILE_NAME"));
//						s.setACHM_SOC_NO(rs.getString("ACHM_SOC_NO"));
//						s.setACHM_TRN_DATE(rs.getString("ACHM_TRN_DATE"));
//						s.setACHM_SEQ_NO(rs.getString("ACHM_SEQ_NO"));
//						s.setACHM_JRNL_NO(rs.getString("ACHM_JRNL_NO"));
//						s.setACHM_ACCT_NO(rs.getString("ACHM_ACCT_NO"));
//						s.setACHM_TXN_BRCH(rs.getString("ACHM_TXN_BRCH"));
//						s.setACHM_HOME_BRANCH(rs.getString("ACHM_HOME_BRANCH"));
//						s.setACHM_USER_NAME(rs.getString("ACHM_USER_NAME"));
//						s.setACHM_AADHAR_NO(rs.getString("ACHM_AADHAR_NO"));
//						s.setACHM_UMRN_NO(rs.getString("ACHM_UMRN_NO"));
//						s.setACHM_USER_NO(rs.getString("ACHM_USER_NO"));
//						s.setACHM_TRAN_CODE(rs.getString("ACHM_TRAN_CODE"));
//						s.setACHM_AMOUNT(rs.getString("ACHM_AMOUNT"));
//						s.setACHM_SET_DATE(rs.getString("ACHM_SET_DATE"));
//						s.setACHM_SET_CYC(rs.getString("ACHM_SET_CYC"));
//						s.setACHM_ERROR_NO(rs.getString("ACHM_ERROR_NO"));
//						s.setACHM_REMITTER_NAME(rs.getString("ACHM_REMITTER_NAME"));
//						s.setACHM_PROD_CODE(rs.getString("ACHM_PROD_CODE"));
//						s.setACHM_STATUS(rs.getString("ACHM_STATUS"));
//						s.setACHM_REQ_REF_NO(rs.getString("ACHM_REQ_REF_NO"));
//						return s;
//					}
//				}).build();
//
//	}
	
	@Bean
	@StepScope
	public JdbcPagingItemReader<ACHMDUP> pagingItemReader(
//			// *** CHANGED: Receiving partitionNumber and gridSize from the partitioner. ***
			@Value("#{stepExecutionContext['partitionNumber']}") Integer partitionNumber,
			@Value("#{stepExecutionContext['gridSize']}") Integer gridSize
			) throws Exception {
//		System.out.println("partition and grid "+partitionNumber+"***"+gridSize);
		LocalDateTime now = LocalDateTime.now();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("ddMMyyyy");
		 String formatted = now.format(formatter);
		String instance = System.getProperty("instance_no");
//		System.out.println("-------------------------------------"+instance+"------------------------------------------");
		Map<String, Object> parameterValues = new HashMap<>();
		parameterValues.put("status", "27");
		parameterValues.put("todaydate", formatted);
		parameterValues.put("instance", instance);
		parameterValues.put("partitionNumber", partitionNumber);
		parameterValues.put("gridSize", gridSize);

		return new JdbcPagingItemReaderBuilder<ACHMDUP>()
				.name("pagingItemReader")
				.dataSource(dataSource())
				.queryProvider(createQueryProvider())
				.parameterValues(parameterValues)
				.pageSize(chunksize)
				.rowMapper(new AchmRowMapper())
				.build();
	}

	@Bean
	public PagingQueryProvider createQueryProvider() throws Exception {
		SqlPagingQueryProviderFactoryBean factory = new SqlPagingQueryProviderFactoryBean();
		
		factory.setDataSource(dataSource());
//		factory.setSelectClause("FILE_NAME,ACHM_SOC_NO,ACHM_TRN_DATE,ACHM_SEQ_NO,ACHM_JRNL_NO,ACHM_ACCT_NO,ACHM_TXN_BRCH,ACHM_HOME_BRANCH,ACHM_USER_NAME,ACHM_AADHAR_NO,ACHM_UMRN_NO,ACHM_USER_NO,ACHM_TRAN_CODE,ACHM_AMOUNT,ACHM_SET_DATE,ACHM_SET_CYC,ACHM_ERROR_NO,ACHM_REMITTER_NAME,ACHM_PROD_CODE,ACHM_STATUS,ACHM_REQ_REF_NO");
//		
//		// *** CRITICAL CHANGE: The FROM clause now includes a subquery to number the rows. ***
//		factory.setFromClause("FROM (select FILE_NAME,ACHM_SOC_NO,ACHM_TRN_DATE,ACHM_SEQ_NO,ACHM_JRNL_NO,ACHM_ACCT_NO,ACHM_TXN_BRCH,ACHM_HOME_BRANCH,ACHM_USER_NAME,ACHM_AADHAR_NO,ACHM_UMRN_NO,ACHM_USER_NO,ACHM_TRAN_CODE,ACHM_AMOUNT,ACHM_SET_DATE,ACHM_SET_CYC,ACHM_ERROR_NO,ACHM_REMITTER_NAME,ACHM_PROD_CODE,ACHM_STATUS,ACHM_REQ_REF_NO from (SELECT FILE_NAME,ACHM_SOC_NO,ACHM_TRN_DATE,ACHM_SEQ_NO,ACHM_JRNL_NO,ACHM_ACCT_NO,ACHM_TXN_BRCH,ACHM_HOME_BRANCH,ACHM_USER_NAME,ACHM_AADHAR_NO,ACHM_UMRN_NO,ACHM_USER_NO,ACHM_TRAN_CODE,ACHM_AMOUNT,ACHM_SET_DATE,ACHM_SET_CYC,ACHM_ERROR_NO,ACHM_REMITTER_NAME,ACHM_PROD_CODE,ACHM_STATUS,ACHM_REQ_REF_NO,ROW_NUMBER() OVER (ORDER BY ACHM_REQ_REF_NO) AS row_num  FROM ACHM WHERE ACHM_STATUS='27')) numbered_rows");
//		
//		// *** CRITICAL CHANGE: The WHERE clause uses MOD to select rows for this partition. ***
//		factory.setWhereClause("WHERE MOD(numbered_rows.row_num, :gridSize) = :partitionNumber");
//		
//		// The sort key is still important for the paging reader to work correctly within its partition.
//		factory.setSortKey("ACHM_REQ_REF_NO");
		
		
		
		factory.setSelectClause("FILE_NAME,ACHM_SOC_NO,ACHM_TRN_DATE,ACHM_SEQ_NO,ACHM_JRNL_NO,ACHM_ACCT_NO,ACHM_TXN_BRCH,ACHM_HOME_BRANCH,ACHM_USER_NAME,ACHM_AADHAR_NO,ACHM_UMRN_NO,ACHM_USER_NO,ACHM_TRAN_CODE,ACHM_AMOUNT,ACHM_SET_DATE,ACHM_SET_CYC,ACHM_ERROR_NO,ACHM_REMITTER_NAME,ACHM_PROD_CODE,ACHM_STATUS,ACHM_REQ_REF_NO");
		
		// *** CRITICAL CHANGE: The FROM clause now includes a subquery to number the rows. ***
		factory.setFromClause("FROM (SELECT t.*, ROW_NUMBER() OVER (ORDER BY ACHM_REQ_REF_NO) as row_num FROM ACHM t WHERE t.ACHM_STATUS = :status and t.ACHM_TRN_DATE =:todaydate and t.BATCH_NUMBER =:instance ) numbered_rows");
		
		// *** CRITICAL CHANGE: The WHERE clause uses MOD to select rows for this partition. ***
		factory.setWhereClause("WHERE MOD(numbered_rows.row_num, :gridSize) = :partitionNumber");
		
		// The sort key is still important for the paging reader to work correctly within its partition.
		factory.setSortKey("ACHM_REQ_REF_NO");
		
		return factory.getObject();
	}
	
	private static final class AchmRowMapper implements RowMapper<ACHMDUP> {
		@Override
		public ACHMDUP mapRow(ResultSet rs, int rowNum) throws SQLException {
			ACHMDUP s = new ACHMDUP();
			s.setFILE_NAME(rs.getString("FILE_NAME"));
			s.setACHM_SOC_NO(rs.getString("ACHM_SOC_NO"));
			s.setACHM_TRN_DATE(rs.getString("ACHM_TRN_DATE"));
			s.setACHM_SEQ_NO(rs.getString("ACHM_SEQ_NO"));
			s.setACHM_JRNL_NO(rs.getString("ACHM_JRNL_NO"));
			s.setACHM_ACCT_NO(rs.getString("ACHM_ACCT_NO"));
			s.setACHM_TXN_BRCH(rs.getString("ACHM_TXN_BRCH"));
			s.setACHM_HOME_BRANCH(rs.getString("ACHM_HOME_BRANCH"));
			s.setACHM_USER_NAME(rs.getString("ACHM_USER_NAME"));
			s.setACHM_AADHAR_NO(rs.getString("ACHM_AADHAR_NO"));
			s.setACHM_UMRN_NO(rs.getString("ACHM_UMRN_NO"));
			s.setACHM_USER_NO(rs.getString("ACHM_USER_NO"));
			s.setACHM_TRAN_CODE(rs.getString("ACHM_TRAN_CODE"));
			s.setACHM_AMOUNT(rs.getString("ACHM_AMOUNT"));
			s.setACHM_SET_DATE(rs.getString("ACHM_SET_DATE"));
			s.setACHM_SET_CYC(rs.getString("ACHM_SET_CYC"));
			s.setACHM_ERROR_NO(rs.getString("ACHM_ERROR_NO"));
			s.setACHM_REMITTER_NAME(rs.getString("ACHM_REMITTER_NAME"));
			s.setACHM_PROD_CODE(rs.getString("ACHM_PROD_CODE"));
			s.setACHM_STATUS(rs.getString("ACHM_STATUS"));
			s.setACHM_REQ_REF_NO(rs.getString("ACHM_REQ_REF_NO"));
			return s;
		}
	}
	
	
	public Step checkDataStep() {
		return stepBuilderFactory.get("checkDataStep")
				.tasklet((contribution,chunkContext) -> {
					Integer dataAvailable=isDataAvailable();
					
					if (dataAvailable!=null && dataAvailable>0) {
						contribution.setExitStatus(new ExitStatus("DATA FOUND"));
					}else {
						contribution.setExitStatus(new ExitStatus("NO DATA FOUND"));
					}
					return RepeatStatus.FINISHED;
				})
				.build();
	}
	
	

	public Integer isDataAvailable() {
		String sql = "Select /*+ INDEX(ACHM idx_achm_status_reqref) */count(ACHM_REQ_REF_NO) from Achm where ACHM_STATUS=?";
		int totalRecord = jdbcTemplate.queryForObject(sql, new Object[] { "27" }, Integer.class);
		return totalRecord;

	}
	
	
	
	
	

	public PlatformTransactionManager getTransactionManager() throws Exception {
		return new ResourcelessTransactionManager();
	}

	@Bean
	public JobRepository getJobRepository() throws Exception    {
		JobRepositoryFactoryBean factory = new JobRepositoryFactoryBean();
		factory.setDataSource(dataSource());
		factory.setTransactionManager(getTransactionManager());
		factory.setIsolationLevelForCreate("ISOLATION_READ_COMMITTED");
		factory.afterPropertiesSet();
		return factory.getObject();
	}

	@Bean
	public JobLauncher getJobLauncher() throws Exception {
		SimpleJobLauncher jobLauncher = new SimpleJobLauncher();
		jobLauncher.setJobRepository(getJobRepository());
		jobLauncher.afterPropertiesSet();
		return jobLauncher;
	}

	@Bean
	public TaskExecutor taskExecutor() {

		ThreadPoolTaskExecutor taskExecutor = new ThreadPoolTaskExecutor();
		taskExecutor.setMaxPoolSize(300);
		taskExecutor.setCorePoolSize(300);
		taskExecutor.setQueueCapacity(500);
		
		return taskExecutor;

	}

	@Bean
	public PartitionHandler partitionHandler() throws Exception {
		TaskExecutorPartitionHandler handler = new TaskExecutorPartitionHandler();
		handler.setTaskExecutor(taskExecutor());
		handler.setStep(MRTranStep());
		handler.setGridSize(50);
		return handler;
	}

}
