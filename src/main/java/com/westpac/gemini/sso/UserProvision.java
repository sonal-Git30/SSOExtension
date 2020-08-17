package com.westpac.gemini.sso;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserProvision {
	
	private Map<String, String> attributes;
	
	private List<String> securityGroups;
	
	private String firstName;
	
	private String lastName;
	
	private String email;
	
	private String primaryCompanyGuid; 
	
	private String locale;
	
	/**
	 * Void constructor
	 */
	public UserProvision() {
		 this.attributes = new HashMap<String, String>();
		 // Making these non-null to avoid exception (should I?)
		 this.securityGroups = new ArrayList<String>();
		 this.firstName = "";
		 this.lastName = "";
		 this.email = "";
		 this.primaryCompanyGuid = "";
		 this.locale = "";
	}

	public Map<String, String> getAttributes() {
		return this.attributes;
	}
	
	public void addToSecurityGroups(String securityGroupName) {
		this.securityGroups.add(securityGroupName);
	}
	
	public List<String> getSecurityGroups() {
		return this.securityGroups;
	}
	
	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}
	
	public String getFirstName() {
		return this.firstName;
	}
	
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	
	public String getLastName() {
		return this.lastName;
	}
	
	public void setEmail(String email) {
		this.email = email;
	}
	
	public String getEmail() {
		return this.email;
	}
	
	public void setPrimaryCompanyGuid(String primaryCompanyGuid) {
		this.primaryCompanyGuid = primaryCompanyGuid;
	}
	
	public String getPrimaryCompanyGuid() {
		return this.primaryCompanyGuid;
	}
	
	public void setLocale(String locale) {
		this.locale = locale;
	}
	
	public String getLocale() {
		return this.locale;
	}	
}