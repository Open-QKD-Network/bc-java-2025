package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.Security;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchProviderException;
import javax.crypto.KeyGenerator;
import java.util.logging.Logger;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPublicKey;

import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;

public class PQCAgreement
    implements TlsAgreement
{
    static final Logger LOG = Logger.getLogger(PQCAgreement.class.getName());

    public enum Role {
        CLIENT,
	SERVER
    }

    protected Role role;
    protected KeyPair localKeyPair;
    protected byte[] peerData;
    protected byte[] sharedSecret;
    protected AlgorithmParameterSpec algorithmParameterSpec;

    public PQCAgreement(AlgorithmParameterSpec spec, Role role)
    {
        this.algorithmParameterSpec = spec;
        this.role = role;
        initialize();
    }

    public byte[] generateEphemeral() throws IOException
    {
        if (role == Role.CLIENT)
        {
            // return public key
            if (algorithmParameterSpec instanceof MLKEMParameterSpec)
            {
                BCMLKEMPublicKey pubk = (BCMLKEMPublicKey) localKeyPair.getPublic();
		MLKEMPublicKeyParameters pkp = (MLKEMPublicKeyParameters) PublicKeyFactory.createKey(pubk.getEncoded());
                byte[] rawKey = pkp.getEncoded();
                return rawKey;
            }
            else
            {
                return null;
            }
        }
        else
        {
            try
            {
                // peerData is public key, calculate shared secret and return cipher text
                if (algorithmParameterSpec instanceof MLKEMParameterSpec)
                {
                    MLKEMPublicKeyParameters fpukp = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_1024, peerData);
                    PublicKey pubKey = new BCMLKEMPublicKey(fpukp);
                    KEMGenerateSpec.Builder builder = new KEMGenerateSpec.Builder(pubKey, "AES", 256);
                    builder.withNoKdf();
                    KEMGenerateSpec spec = builder.build();
                    KeyGenerator keygen = KeyGenerator.getInstance("ML-KEM", "BC");
                    keygen.init(spec, new SecureRandom());

                    SecretKeyWithEncapsulation secEncap = (SecretKeyWithEncapsulation)keygen.generateKey();
                    this.sharedSecret = secEncap.getEncoded();
                    byte[] ct = secEncap.getEncapsulation();
                    LOG.info("PQCAgreement.generateEphemeral, cipher text length:" + ct.length + ",shared key length:" + sharedSecret.length);
                    return ct;
                }
            }
            catch (NoSuchAlgorithmException e)
            {
                LOG.info("PQCAgreement.generateEphemeral, NoSuchAlgorithmException:" + e);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                LOG.info("PQCAgreement.generateEphemeral, InvalidAlgorithmParameterException:" + e);
            }
            catch (NoSuchProviderException e)
            {
                LOG.info("PQCAgreement.generateEphemeral, NoSuchProviderException:" + e);
            }
            return null;
        }
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.peerData = peerValue.clone();
    }

    public TlsSecret calculateSecret() throws IOException
    {
        try
        {
            if (role == Role.SERVER)
            {
                if (algorithmParameterSpec instanceof MLKEMParameterSpec)
                {
                    return new JceTlsSecret(null, this.sharedSecret);
                }
            }
            else
            {
                if (algorithmParameterSpec instanceof MLKEMParameterSpec)
                {
                    KEMExtractSpec.Builder builder = new KEMExtractSpec.Builder(this.localKeyPair.getPrivate(), this.peerData, "AES", 256);
                    builder.withNoKdf();
                    KEMExtractSpec spec = builder.build();
                    KeyGenerator keygen = KeyGenerator.getInstance("ML-KEM", "BC");
                    keygen.init(spec);
                    // calculate the shared secret
                    SecretKeyWithEncapsulation enc = (SecretKeyWithEncapsulation) keygen.generateKey();
                    this.sharedSecret = enc.getEncoded();
                    return new JceTlsSecret(null, this.sharedSecret);
                }
            }
        }
        catch (Exception e)
        {
            LOG.info("PQCAgreement.calculateSecret, throws exception:" + e);
        }
        return null;
    }

    private void initialize()
    {
        /*if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }*/

        if (this.role == Role.SERVER)
        {
            // For server, we do not need to generate keypair.
            return;
        }
        try
        {
            if (algorithmParameterSpec instanceof MLKEMParameterSpec)
            {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
                kpg.initialize(this.algorithmParameterSpec, new SecureRandom());
                this.localKeyPair = kpg.generateKeyPair();
            }
        }
        catch (Exception e)
        {
            LOG.info("PQCAgreement.initialize, throws exception:" + e);
        }
    }
}
