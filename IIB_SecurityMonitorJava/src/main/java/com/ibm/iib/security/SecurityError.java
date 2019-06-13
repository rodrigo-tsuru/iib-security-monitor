package com.ibm.iib.security;

public class SecurityError {

	private String message;
	private String ref;

	public SecurityError(String message, String ref) {
		this.message = message;
		this.ref = ref;
	}
	
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	public String getRef() {
		return ref;
	}
	public void setRef(String ref) {
		this.ref = ref;
	}

}
