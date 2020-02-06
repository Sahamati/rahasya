package io.yaazhi.forwardsecrecy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

@SpringBootApplication

public class ForwardSecrecyApplication {

	public static void main(String[] args) {
		
		Security.addProvider(new BouncyCastleProvider());
		SpringApplication.run(ForwardSecrecyApplication.class, args);
		
	}

}
