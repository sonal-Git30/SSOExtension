package com.westpac.gemini.sso;

import com.adminserver.bll.SystemDateBll;
import com.adminserver.dal.ISecondaryDataAccessHelper;
import com.adminserver.dcl.AuthorizedUserDcl;
import com.adminserver.dcl.DataDcl;
import com.adminserver.dcl.SystemInformationDcl;
import com.adminserver.math.bus.DataRetriever;
import com.adminserver.model.AsUserModel;
import com.adminserver.pas.bll.AuthorizedUserBll;
import com.adminserver.pas.model.LoginModel;
import com.adminserver.pas.uip.LoginUip;
import com.adminserver.pas.uip.extensibility.UipExtensionContext;
import com.adminserver.utl.SpringBeanUtl;
import com.adminserver.utl.exception.AsExceptionUtl;
import com.adminserver.web.session.RequestContext;
import com.oracle.pas.page.LoginPage;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;

public class SSOExtensionUip implements com.adminserver.pas.uip.extensibility.IUipExtension
{
  Logger logger = Logger.getLogger(SSOExtensionUip.class.getName());
  //String parentCompGuid = "49AE5DC3-B564-46BF-91DE-9E5B8612B60C";
  public SSOExtensionUip() {}
  
  public boolean processPre(UipExtensionContext extensionContext) { String clientNumber = "";
    UserProvision userProvision = new UserProvision();
    Logger logger = Logger.getLogger(SSOExtensionUip.class.getName());
    
    boolean result = false;
    

    HttpServletRequest request = RequestContext.getCurrentRequest();
    

    Enumeration<String> headerNames = request.getHeaderNames();
    

    String ssoPropertiesFileLocation = (String)SystemInformationDcl.getPropertyMap().get("extensions.ssoPropertiesFile");
    if ((ssoPropertiesFileLocation == null) || (ssoPropertiesFileLocation.isEmpty())) {
      logger.warning("Could not get required property extensions.ssoPropertiesFile from PAS.properties file. Exiting...");
      return result;
    }
    try
    {
      FileReader reader = new FileReader(ssoPropertiesFileLocation);
      BufferedReader textReader = new BufferedReader(reader);
      String line = "";
      while ((line = textReader.readLine()) != null) {
        String[] equalsSplit = line.split("=");
        if (line.startsWith("primaryCompanyGuid")) {
          userProvision.setPrimaryCompanyGuid(equalsSplit[(equalsSplit.length - 1)]);
        }
        else if (line.startsWith("locale")) {
          userProvision.setLocale(equalsSplit[(equalsSplit.length - 1)]);
        }
      }
      
      textReader.close();
    } catch (FileNotFoundException e) {
      e.printStackTrace();
      logger.warning("Could not find sso.properties file at location of " + ssoPropertiesFileLocation + ". Exiting...");
      return result;
    } catch (IOException e) {
      e.printStackTrace();
      logger.warning("Could not read from sso.properties file at location of " + ssoPropertiesFileLocation + ". Exiting...");
      return result;
    }
    
    FileReader reader;
    while (headerNames.hasMoreElements()) {
      String headerName = (String)headerNames.nextElement();
      String headerValue = request.getHeader(headerName);
      if (headerName.equals("OAM_REMOTE_USER")) {
        clientNumber = headerValue;
        logger.log(Level.FINEST, "OAM_REMOTE_USER: " + headerValue);
        System.out.println("Security groups came for User :"+clientNumber);
      }
      else if (headerName.equals("OAM_REMOTE_FIRSTNAME")) {
        userProvision.setFirstName(headerValue);
        logger.log(Level.FINEST, "OAM_REMOTE_FIRSTNAME: " + headerValue);
      }
      else if (headerName.equals("OAM_REMOTE_LASTNAME")) {
        userProvision.setLastName(headerValue);
        logger.log(Level.FINEST, "OAM_REMOTE_LASTNAME: " + headerValue);
      }
      else if (headerName.equals("OAM_REMOTE_EMAILADDRESS")) {
        userProvision.setEmail(headerValue);
        logger.log(Level.FINEST, "OAM_REMOTE_EMAIL: " + headerValue);
      }
      else if (headerName.equals("OAM_REMOTE_GROUP")) {
        String[] values = headerValue.split(":");
        for (String value : values) {
          userProvision.addToSecurityGroups(value);
          System.out.println("Security group came for User :"+clientNumber+ " Groupname : " + value);
        }
        logger.log(Level.FINEST, "OAM_REMOTE_GROUP: " + headerValue);
      }
    }
    

    if (!clientNumber.isEmpty())
    {
      result = handleOIPAUser(clientNumber, userProvision);
      
      if (!result)
      {
        LoginModel loginModel = (LoginModel)extensionContext.getCurrentForm().getModel();
        LoginPage loginPage = (LoginPage)extensionContext.getCurrentForm();
        System.out.println("****************loginPage for user :"+clientNumber+ " -- "+ loginPage.getPageName());
        loginModel.setClientNumber(clientNumber);
        AuthorizedUserBll authorizedUserBll = (AuthorizedUserBll)SpringBeanUtl.getBean(AuthorizedUserBll.class);
        //tiru
        AuthorizedUserDcl authorizedUserDcl = authorizedUserBll.loadUser(loginModel.getClientNumber(), true, userProvision.getPrimaryCompanyGuid()); //null
        System.out.println("****************after setting  authorizedUserDcl : "+ authorizedUserDcl);
        loginModel.getUserModel().setAuthorizedUserDcl(authorizedUserDcl);
        LoginUip loginUip = (LoginUip)SpringBeanUtl.getBean(LoginUip.class);
        System.out.println("****************loginUip before setupUserModel : "+ loginUip);
        loginUip.setupUserModel(loginPage);  
        System.out.println("****************after setupUserModel for user : "+ clientNumber );
        loginModel.getUserModel().setAuthenticated((authorizedUserDcl.getSecurityGroupList() != null) && (!authorizedUserDcl.getSecurityGroupList().isEmpty()));
        loginUip.loadAuthenticatedUserSecurityModel(loginPage);
        System.out.println("****************End of ProcessPre method : ");
      }
    }
    
    return true;
  }
  
  private boolean handleOIPAUser(String clientNumber, UserProvision userProvision) {
    boolean showLoginScreen = true;
    
    try {
		boolean isUser = checkOIPAUser(clientNumber);
		if (!isUser) {
		  boolean isGroup = checkSecurityGroups(userProvision);
		  if (isGroup)
		  {
		    createNewOipaUser(clientNumber, userProvision);
		    
		    addSecurityGroups(clientNumber, userProvision.getSecurityGroups(),userProvision);
		    showLoginScreen = false;
		  }
		  else
		  {
		    logger.info("Could not find valid security group from HTTP header.");
		  }
		}
		else
		{
		  handleNewSecurityGroups(clientNumber, userProvision);
		  
		  updateEffectiveDates(clientNumber, userProvision.getSecurityGroups(),userProvision);
		   
		  handleExistingSecurityGroups(clientNumber, userProvision); // new method to invalidate deleted sec grps in OID. -tiru
		  showLoginScreen = false;
		}
	} catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
    return showLoginScreen;
  }
  
  private void handleNewSecurityGroups(String clientNumber, UserProvision userProvision) {
    DataRetriever dataRetriever = (DataRetriever)SpringBeanUtl.getBeanByClassName("DataRetrieverDal");
    
    List<String> groupsToCheck = userProvision.getSecurityGroups();
    String clientGuid = getClientGuid(clientNumber);
    
    for (String groupName : groupsToCheck) {
      List<Object> parameters = new ArrayList();
      parameters.add(groupName);
      List<DataDcl> nameExists = dataRetriever.executePreparedStatement(checkSecurityGroupExistsSql(), parameters.toArray());
      

      if (nameExists.size() > 0) {
        String securityGroupGuid = getSecurityGroupGuid(groupName);
        
        if ((securityGroupGuid != null) && (!securityGroupGuid.isEmpty())) {
          List<Object> secParameters = new ArrayList();
          secParameters.add(securityGroupGuid);
          secParameters.add(clientGuid);
          List<DataDcl> securityGroupExists = dataRetriever.executePreparedStatement(checkUserSecurityGroupExistsSql(), secParameters.toArray());
          

          if (securityGroupExists.size() == 0) {
            System.out.println("Adding security group for user : "+ clientGuid +" new group name :" + groupName);
            List<Object> addParameters = new ArrayList();
            
            addParameters.add(securityGroupGuid);
            
            addParameters.add(clientGuid);
            //tiru
            addParameters.add(SystemDateBll.getSystemDate(userProvision.getPrimaryCompanyGuid()));
            addParameters.add(SystemDateBll.getSystemDate(userProvision.getPrimaryCompanyGuid()));
            
            getSecondaryDataAccessHelper().executeSqlUpdate(addSecurityGroupsSQL(), addParameters.toArray());
          }
        }
      }
    }
  }
  // New method to invalidate deleted sec groups in OID -- Tiru
  private void handleExistingSecurityGroups(String clientNumber, UserProvision userProvision) {
	  try {
		DataRetriever dataRetriever = (DataRetriever)SpringBeanUtl.getBeanByClassName("DataRetrieverDal");
		  List<String> extSecurityGroupGuidsToRemove = new <String> ArrayList();
		  List<String> groupsToCheck = userProvision.getSecurityGroups();
		  String clientGuid = getClientGuid(clientNumber);
		  List<Object> parameters = new ArrayList();
		  parameters.add(clientGuid);
		  // existing user sec grps
		  List<DataDcl> extSecurityGroupGuids1 = dataRetriever.executePreparedStatement(checkUserSecurityGroupsExistsSql(), parameters.toArray());
		  List<String> extSecurityGroupGuids = new ArrayList();
		  for (DataDcl dataDcl : extSecurityGroupGuids1) {
			  extSecurityGroupGuids.add((String)dataDcl.getValue(1));
		  }
		  System.out.println("User existing secGroups for : "+ clientNumber +" size :" + extSecurityGroupGuids.size());
		  
		  // incoming user sec grps
		  for (String groupName : groupsToCheck) {
			  List<Object> parameterrs = new ArrayList();
			  parameterrs.add(groupName);
			  List<DataDcl> nameExists = dataRetriever.executePreparedStatement(checkSecurityGroupExistsSql(), parameterrs.toArray());
			  if (nameExists.size() > 0) {
				  String securityGroupGuid = getSecurityGroupGuid(groupName);
				  extSecurityGroupGuidsToRemove.add(securityGroupGuid);
			  }
		  }
		  
		  extSecurityGroupGuids.removeAll(extSecurityGroupGuidsToRemove);
		  System.out.println("User sec groups to be invalidated for : "+ clientNumber +" size :" + extSecurityGroupGuids.size());
		  
		  // Now update the dates to remaining sec grps to invalidate
		  if (!extSecurityGroupGuids.isEmpty() & extSecurityGroupGuids.size() > 0) {
			  for (String dataDcl : extSecurityGroupGuids) {
				  String secGroupGuid = dataDcl;
				  if ((secGroupGuid != null) && (!secGroupGuid.isEmpty())) {
					  List<Object> params = new ArrayList();
					 // params.add(SystemDateBll.getSystemDate(userProvision.getPrimaryCompanyGuid()));
					  params.add(secGroupGuid);
					  params.add(clientNumber);
					 // commented to delete sec group instead of invalidating (SSO sync issues) - Tiru
					 // getSecondaryDataAccessHelper().executeSqlUpdate(updateExistingSecGrpEffectiveToSql(), params.toArray());
					  getSecondaryDataAccessHelper().executeSqlUpdate(deleteExistingSecGrpSql(), params.toArray()); 
					  System.out.println("Deleted invalid sec group for : "+ clientNumber +" groupname :" + secGroupGuid);
				  } //deleteExistingSecGrpSql
			  }
		  }
	} catch (NullPointerException ne) {
		// TODO Auto-generated catch block
		System.out.println("Null exception in ----- Updated existing sec grop  : " );
		ne.printStackTrace();
	}	catch (AsExceptionUtl e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
  }
 
  
  private boolean checkSecurityGroups(UserProvision userProvision)
  {
    boolean result = false;
    DataRetriever dataRetriever = (DataRetriever)SpringBeanUtl.getBeanByClassName("DataRetrieverDal");
    
    List<String> groupsToCheck = userProvision.getSecurityGroups();
    for (String groupName : groupsToCheck) {
      List<Object> parameters = new ArrayList();
      parameters.add(groupName);
      List<DataDcl> securityGroup = dataRetriever.executePreparedStatement(checkSecurityGroupExistsSql(), parameters.toArray());
      

      if (securityGroup.size() > 0) {
        result = true;
        break;
      }
    }
    return result;
  }
  
  private String getSecurityGroupGuid(String securityGroupName) {
    String securityGroupGuid = "";
    DataRetriever dataRetriever = (DataRetriever)SpringBeanUtl.getBeanByClassName("DataRetrieverDal");
    
    List<Object> parameters = new ArrayList();
    parameters.add(securityGroupName);
    List<DataDcl> securityGroup = dataRetriever.executePreparedStatement(checkSecurityGroupExistsSql(), parameters.toArray());
    
    if (securityGroup.size() > 0) {
      for (DataDcl dataDcl : securityGroup) {
        securityGroupGuid = (String)dataDcl.getValue(1);
      }
    }
    return securityGroupGuid;
  }
  
  private String getClientGuid(String clientNumber) {
    String clientGuid = "";
    DataRetriever dataRetriever = (DataRetriever)SpringBeanUtl.getBeanByClassName("DataRetrieverDal");
    
    List<Object> parameters = new ArrayList();
    parameters.add(clientNumber);
    List<DataDcl> client = dataRetriever.executePreparedStatement(getClientGuidSql(), parameters.toArray());
    if (client.size() > 0) {
      for (DataDcl dataDcl : client) {
        clientGuid = (String)dataDcl.getValue(1);
      }
    }
    return clientGuid;
  }
  
  private ISecondaryDataAccessHelper getSecondaryDataAccessHelper() {
    return com.adminserver.dal.jdbc.JdbcDataAccessHelperFactory.getInstance();
  }
  
  private void updateEffectiveDates(String clientNumber, List<String> securityGroups, UserProvision userProvision) {
    Logger logger = Logger.getLogger(SSOExtensionUip.class.getName());
    logger.log(Level.INFO, "UPDATING EFFECTIVE DATES");
    System.out.println("UPDATING EFFECTIVE DATES "+ clientNumber +" from date :" + SystemDateBll.getSystemDate(userProvision.getPrimaryCompanyGuid()).toString());
    logger.log(Level.INFO, SystemDateBll.getSystemDate(userProvision.getPrimaryCompanyGuid()).toString());
    for (String securityGroup : securityGroups) {
      String securityGroupGuid = getSecurityGroupGuid(securityGroup);
      if ((securityGroupGuid != null) && (!securityGroupGuid.isEmpty())) {
        List<Object> parameters = new ArrayList();
        parameters.add(SystemDateBll.getSystemDate(userProvision.getPrimaryCompanyGuid()));
        parameters.add(getSecurityGroupGuid(securityGroup));
        parameters.add(clientNumber);
        getSecondaryDataAccessHelper().executeSqlUpdate(updateUserEffectiveToSql(), parameters.toArray());
        System.out.println("Updated EFFECTIVE date for : "+ clientNumber +" groupname :" + securityGroup);
      }
    }
  }
  
  private boolean checkOIPAUser(String clientNumber) {
    boolean result = false;
    DataRetriever dataRetriever = (DataRetriever)SpringBeanUtl.getBeanByClassName("DataRetrieverDal");
    
    List<Object> parameters = new ArrayList();
    parameters.add(clientNumber);
    List<DataDcl> userInformation = dataRetriever.executePreparedStatement(checkUserExistsSql(), parameters.toArray());
    
    if (userInformation.size() > 0) {
      result = true;
    }
    return result;
  }
  
  private void createNewOipaUser(String userName, UserProvision userProvision)
  {
    Logger logger = Logger.getLogger(SSOExtensionUip.class.getName());
    logger.info("CREATING NEW USER");
    



    String numberOfIterations = "1234";
    String algorithmCode = "01";
    String randomString = userName;
    




    if (userProvision.getFirstName().isEmpty()) {
      userProvision.setFirstName(userName);
    }
    if (userProvision.getLastName().isEmpty()) {
      userProvision.setLastName(userName);
    }
    


    try
    {
      SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
      StringBuilder randomNumber = new StringBuilder();
      for (int x = 1; x <= 8; x++) {
        randomNumber = randomNumber.append(new Integer(secureRandom.nextInt(10)).toString());
      }
      randomString = randomNumber.toString();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    



    char[] userEnteredPassword = randomString.toCharArray();
    String userPassword = com.westpac.gemini.encryption.EncryptionHelperUtl.encryptPassword(userName, userEnteredPassword, numberOfIterations, algorithmCode);
    




    List<Object> parameters = new ArrayList();
    
    parameters.add(userProvision.getPrimaryCompanyGuid());
    
    parameters.add(userPassword);
    
    parameters.add(userProvision.getFirstName());
    
    parameters.add(userProvision.getLastName());
    
    parameters.add(userName);
    
    parameters.add(userProvision.getEmail());
    
    parameters.add(userProvision.getLocale());
    
    getSecondaryDataAccessHelper().executeSqlUpdate(createNewUserSql(), parameters.toArray());
  }
  
  private String checkUserExistsSql() {
    return "SELECT * FROM ASUSER WHERE CLIENTNUMBER = ?";
  }
  
  private String getClientGuidSql() {
    return "SELECT CLIENTGUID FROM ASUSER WHERE CLIENTNUMBER = ?";
  }
  
  private String checkSecurityGroupExistsSql() {
    return "SELECT SecurityGroupGuid FROM ASSECURITYGROUP WHERE GROUPNAME = ?";
  }
  
  private String checkUserSecurityGroupExistsSql() {
    return "SELECT * FROM ASUSERSECURITYGROUP WHERE SECURITYGROUPGUID = ? AND CLIENTGUID = ?";
  }
  private String checkUserSecurityGroupsExistsSql() {
	  return "SELECT SECURITYGROUPGUID FROM ASUSERSECURITYGROUP WHERE CLIENTGUID = ?";
  }
  
  private String createNewUserSql() {
    StringBuffer sql = new StringBuffer();
    sql.append(" DECLARE\n");
    sql.append(" l_companyGuid CHAR (36) := ?;\n");
    sql.append(" l_encryptedPassword VARCHAR2 (500):= ?;\n");
    sql.append(" l_firstName VARCHAR2 (200):= ?;\n");
    sql.append(" l_lastName VARCHAR2 (200):= ?;\n");
    sql.append(" l_user VARCHAR2 (200):= ?;\n");
    sql.append(" l_clientGuid CHAR (36):= format_guid;\n");
    sql.append(" l_email VARCHAR2 (200):= ?;\n");
    sql.append(" l_locale VARCHAR2 (2):= ?;\n");
    sql.append(" BEGIN\n");
    sql.append(" INSERT INTO AsUser (ClientGuid, ClientNumber, Password, LocaleCode, UserStatus)\n");
    sql.append(" SELECT l_clientGuid, l_user, l_encryptedPassword, l_locale, '01' FROM dual;\n");
    sql.append(" INSERT INTO Asclient (ClientGuid, TypeCode, LastName, Firstname, Sex, UpdatedGmt, EntityTypeCode, Email)\n");
    sql.append(" SELECT l_clientGuid, 99, l_lastName, l_firstName, 'M', sysdate, 'CLIENT', l_email FROM dual;\n");
    sql.append(" INSERT INTO AsRole (RoleGuid, CompanyGuid, ClientGuid, Rolecode)\n");
    sql.append(" SELECT format_guid, l_companyGuid, l_clientGuid, '02' FROM dual;\n");
    sql.append(" END;");
    
    return sql.toString();
  }
  
  private void addSecurityGroups(String clientNumber, List<String> securityGroups, UserProvision userProvision) {
    Logger logger = Logger.getLogger(SSOExtensionUip.class.getName());
    logger.log(Level.INFO, "ADDING SECURITY GROUPS");
    String clientGuid = getClientGuid(clientNumber);
    


    for (String securityGroup : securityGroups) {
      System.out.println("Adding security group for new user: " + securityGroup);
      


      String securityGroupGuid = getSecurityGroupGuid(securityGroup);
      if ((securityGroupGuid != null) && (!securityGroupGuid.isEmpty())) {
        List<Object> parameters = new ArrayList();
                parameters.add(securityGroupGuid);
               parameters.add(clientGuid);
              parameters.add(SystemDateBll.getSystemDate(userProvision.getPrimaryCompanyGuid()));
        parameters.add(SystemDateBll.getSystemDate(userProvision.getPrimaryCompanyGuid()));
      
        getSecondaryDataAccessHelper().executeSqlUpdate(addSecurityGroupsSQL(), parameters.toArray());
        System.out.println("Added security group: " + securityGroup +"for client guid: "+ clientGuid);
      }
    }
  }
  
  /*private void addSecurityGroup(String clientNumber, String securityGroup) {
    Logger logger = Logger.getLogger(SSOExtensionUip.class.getName());
    logger.log(Level.INFO, "ADDING SECURITY GROUP");
    String clientGuid = getClientGuid(clientNumber);
    
    System.out.println("Adding security group: " + securityGroup);
    


    String securityGroupGuid = getSecurityGroupGuid(securityGroup);
    if ((securityGroupGuid != null) && (!securityGroupGuid.isEmpty())) {
      List<Object> parameters = new ArrayList();
      
      parameters.add(securityGroupGuid);
      
      parameters.add(clientGuid);
      
      parameters.add(SystemDateBll.getSystemDate(parentCompGuid));
      parameters.add(SystemDateBll.getSystemDate(parentCompGuid));
      
      getSecondaryDataAccessHelper().executeSqlUpdate(addSecurityGroupsSQL(), parameters.toArray());
    }
  }
  */
  private String addSecurityGroupsSQL()
  {
    StringBuffer sql = new StringBuffer();
    
    sql.append(" DECLARE\n");
    sql.append(" l_securityGroupGuid CHAR (36):= ?;\n");
    sql.append(" l_clientGuid CHAR (36):= ?;\n");
    sql.append(" BEGIN\n");
    sql.append(" INSERT INTO AsUserSecurityGroup (SecurityGroupGuid, ClientGuid, RoleEffectiveFrom, RoleEffectiveTo)\n");
    sql.append(" SELECT l_securityGroupGuid, l_clientGuid, ?, ? + 2 FROM dual;\n");
    sql.append(" END;");
    
    return sql.toString();
  }
  
  private String updateUserEffectiveToSql() {
    return "UPDATE AsUserSecurityGroup SET RoleEffectiveTo = ? + 2 WHERE SecurityGroupGuid = ? AND ClientGuid IN (SELECT ClientGuid FROM AsUser WHERE ClientNumber = ?)";
  }
  private String updateExistingSecGrpEffectiveToSql() {
	  return "UPDATE AsUserSecurityGroup SET RoleEffectiveTo = ? - 1 WHERE SecurityGroupGuid = ? AND ClientGuid IN (SELECT ClientGuid FROM AsUser WHERE ClientNumber = ?)";
  }
  private String deleteExistingSecGrpSql() {
	  return "DELETE from AsUserSecurityGroup WHERE SecurityGroupGuid = ? AND ClientGuid IN (SELECT ClientGuid FROM AsUser WHERE ClientNumber = ?)";
  }
  public void processPost(UipExtensionContext extensionContext) {}
}
 
