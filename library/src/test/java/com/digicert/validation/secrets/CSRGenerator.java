package com.digicert.validation.secrets;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Generates a CSR using the BouncyCastle library
 */
@Slf4j
public class CSRGenerator {

    public CSRGenerator(){
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generates a key pair if one has not already been generated. This is not in the constructor because of the exception handling.
     */
    KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    /***
     * Generates a CSR using the provided common name
     * @param commonName the common name to use in the CSR
     * @return a CSR in PEM format
     */
    public String generateCSR(String commonName) throws NoSuchAlgorithmException, IOException, OperatorCreationException {

        KeyPair keyPair = generateKeyPair();
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {

            X500Name subject = new X500Name("CN=" + commonName);
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
            ContentSigner signer = csBuilder.build(keyPair.getPrivate());
            PKCS10CertificationRequest certificationRequest = p10Builder.build(signer);

            pemWriter.writeObject(certificationRequest);
        }

        return writer.toString();
    }
}
