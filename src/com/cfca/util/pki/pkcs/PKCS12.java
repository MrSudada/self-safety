//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.cfca.util.pki.pkcs;


import com.cfca.util.pki.PKIException;
import com.cfca.util.pki.Parser;
import com.cfca.util.pki.asn1.ASN1EncodableVector;
import com.cfca.util.pki.asn1.ASN1InputStream;
import com.cfca.util.pki.asn1.ASN1OctetString;
import com.cfca.util.pki.asn1.ASN1Sequence;
import com.cfca.util.pki.asn1.ASN1Set;
import com.cfca.util.pki.asn1.DEREncodable;
import com.cfca.util.pki.asn1.DERInteger;
import com.cfca.util.pki.asn1.DERObjectIdentifier;
import com.cfca.util.pki.asn1.DEROctetString;
import com.cfca.util.pki.asn1.DEROutputStream;
import com.cfca.util.pki.asn1.DERSequence;
import com.cfca.util.pki.asn1.DERSet;
import com.cfca.util.pki.asn1.pkcs.Attribute;
import com.cfca.util.pki.asn1.pkcs.PKCSObjectIdentifiers;
import com.cfca.util.pki.asn1.pkcs.RSAPrivateKeyStructure;
import com.cfca.util.pki.asn1.pkcs.pkcs12.AuthenticatedSafe;
import com.cfca.util.pki.asn1.pkcs.pkcs12.CertBag;
import com.cfca.util.pki.asn1.pkcs.pkcs12.MacData;
import com.cfca.util.pki.asn1.pkcs.pkcs12.PKCS12PBEParams;
import com.cfca.util.pki.asn1.pkcs.pkcs12.Pfx;
import com.cfca.util.pki.asn1.pkcs.pkcs12.SafeBag;
import com.cfca.util.pki.asn1.pkcs.pkcs12.SafeContents;
import com.cfca.util.pki.asn1.pkcs.pkcs7.ContentInfo;
import com.cfca.util.pki.asn1.pkcs.pkcs7.EncryptedContentInfo;
import com.cfca.util.pki.asn1.pkcs.pkcs7.EncryptedData;
import com.cfca.util.pki.asn1.pkcs.pkcs8.PrivateKeyInfo;
import com.cfca.util.pki.asn1.x509.AlgorithmIdentifier;
import com.cfca.util.pki.asn1.x509.DigestInfo;
import com.cfca.util.pki.asn1.x509.X509CertificateStructure;
import com.cfca.util.pki.cert.X509Cert;
import com.cfca.util.pki.cipher.JCrypto;
import com.cfca.util.pki.cipher.JKey;
import com.cfca.util.pki.cipher.Mechanism;
import com.cfca.util.pki.cipher.lib.JSoftLib;
import com.cfca.util.pki.cipher.param.CBCParam;
import com.cfca.util.pki.encoders.Base64;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Vector;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.spec.PBEParameterSpec;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.PaddedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

public class PKCS12 {
    private Pfx pfx = null;
    private CertBag[] certBags = null;
    private DEREncodable privateKeyInfo = null;
    private ContentInfo keyContent = null;
    private ContentInfo certContent = null;
    private byte[] password = null;
    private boolean decrypted = false;
    private static final int ITERATIONS = 2000;
    private JSoftLib jSoftLib = new JSoftLib();

    public PKCS12() {
        this.decrypted = false;
    }

    public void load(Pfx _pfx) {
        this.pfx = _pfx;
    }

    public void load(String fileName) throws PKIException {
        try {
            FileInputStream fin = new FileInputStream(fileName);
            byte[] data = new byte[fin.available()];
            fin.read(data);
            fin.close();
            this.load(data);
        } catch (Exception var4) {
            throw new PKIException("850605", "载入P12对象错误", var4);
        }
    }

    public void load(InputStream ins) throws PKIException {
        try {
            ASN1InputStream ais = new ASN1InputStream(ins);
            this.pfx = Pfx.getInstance(ais.readObject());
            ais.close();
            ins.close();
        } catch (Exception var3) {
            throw new PKIException("850605", "载入P12对象错误", var3);
        }
    }

    public void load(byte[] data) throws PKIException {
        boolean isB64 = Parser.isBase64Encode(data);
        if (isB64) {
            data = Parser.convertBase64(data);
            data = Base64.decode(data);
        }

        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ASN1InputStream ais = new ASN1InputStream(bis);
            this.pfx = Pfx.getInstance(ais.readObject());
            ais.close();
            bis.close();
        } catch (Exception var5) {
            throw new PKIException("850605", "载入P12对象错误", var5);
        }
    }

    public void decrypt(char[] _password) throws PKIException {
        try {
            if (this.pfx == null) {
                throw new Exception("you must load Pfx first.");
            } else {
                this.password = PKCS12ParametersGenerator.PKCS12PasswordToBytes(_password);
                if (!this.verifyMac()) {
                    throw new Exception("verifyMac faulture.");
                } else {
                    ContentInfo authSafe = this.pfx.getAuthSafe();
                    ASN1OctetString octetString = ASN1OctetString.getInstance(authSafe.getContent());
                    ASN1Sequence sequence = this.oct2Seq(octetString);
                    AuthenticatedSafe authenticatedSafe = AuthenticatedSafe.getInstance(sequence);
                    ContentInfo[] contentInfo = authenticatedSafe.getContentInfo();

                    for(int i = 0; i < contentInfo.length; ++i) {
                        if (contentInfo[i].getContentType().equals(PKCSObjectIdentifiers.data)) {
                            this.keyContent = contentInfo[i];
                        } else if (contentInfo[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData)) {
                            this.certContent = contentInfo[i];
                        }
                    }

                    this.handleKeyContent(this.keyContent);
                    this.handleCertContent(this.certContent);
                    this.decrypted = true;
                }
            }
        } catch (Exception var8) {
            throw new PKIException("850606", "解析P12失败，请重新确认解密口令", var8);
        }
    }

    public JKey getPrivateKey() throws PKIException {
        try {
            if (!this.decrypted) {
                throw new Exception("pfx file hasn't been decrypted yet.");
            } else {
                ASN1Sequence s = (ASN1Sequence)this.privateKeyInfo;
                PrivateKeyInfo pki = new PrivateKeyInfo(s);
                PKCS8EncodedKeySpec p8KeySpec = new PKCS8EncodedKeySpec(Parser.writeDERObj2Bytes(s));
                return pki.getAlgorithmId().getObjectId().equals(PKCSObjectIdentifiers.rsaEncryption) ? new JKey("RSA_Private", p8KeySpec.getEncoded()) : null;
            }
        } catch (Exception var4) {
            throw new PKIException("850607", "获取P12私钥失败", var4);
        }
    }

    public X509Cert[] getCerts() throws PKIException {
        try {
            if (!this.decrypted) {
                throw new Exception("pfx file hasn't been decrypted yet.");
            } else {
                ASN1OctetString oct = null;
                ASN1Sequence seq = null;
                Vector v = new Vector();

                for(int i = 0; i < this.certBags.length; ++i) {
                    DERObjectIdentifier certId = this.certBags[i].getCertId();
                    if (certId.equals(PKCSObjectIdentifiers.x509certType)) {
                        oct = ASN1OctetString.getInstance(this.certBags[i].getCertValue());
                        seq = this.oct2Seq(oct);
                        X509CertificateStructure certStruc = X509CertificateStructure.getInstance(seq);
                        X509Cert cert = new X509Cert(certStruc);
                        v.add(cert);
                    } else if (!certId.equals(PKCSObjectIdentifiers.sdsiCertType)) {
                        throw new Exception("not support certBag type, id=" + certId.getId());
                    }
                }

                X509Cert[] certs = new X509Cert[v.size()];
                v.toArray(certs);
                return certs;
            }
        } catch (Exception var8) {
            throw new PKIException("850608", "获取P12公钥证书失败", var8);
        }
    }

    public X509Cert getCertificate() throws PKIException {
        X509Cert[] certs = this.getCerts();
        return certs != null ? certs[0] : null;
    }

    private boolean verifyMac() throws Exception {
        MacData macData = this.pfx.getMacData();
        DigestInfo digestInfo = macData.getMac();
        DERObjectIdentifier oid = digestInfo.getAlgorithmId().getObjectId();
        PKCS12ParametersGenerator p12gen = null;
        int keyLen = 0;
        Mechanism macM = null;
        if (oid.equals(PKCSObjectIdentifiers.sha1)) {
            p12gen = new PKCS12ParametersGenerator(new SHA1Digest());
            keyLen = 160;
            macM = new Mechanism("HMac-SHA1");
        } else if (oid.equals(PKCSObjectIdentifiers.md2)) {
            p12gen = new PKCS12ParametersGenerator(new MD2Digest());
            keyLen = 128;
            macM = new Mechanism("HMac-MD2");
        } else {
            if (!oid.equals(PKCSObjectIdentifiers.md5)) {
                throw new Exception("not support digest algorithmIdentifier:" + oid);
            }

            p12gen = new PKCS12ParametersGenerator(new MD5Digest());
            keyLen = 128;
            macM = new Mechanism("HMac-MD5");
        }

        byte[] salt = macData.getSalt();
        int iterations = macData.getIterationCount().intValue();
        p12gen.init(this.password, salt, iterations);
        CipherParameters param = p12gen.generateDerivedMacParameters(keyLen);
        KeyParameter keyParam = (KeyParameter)param;
        JKey macKey = new JKey("DESede", keyParam.getKey());
        ASN1OctetString oct = ASN1OctetString.getInstance(this.pfx.getAuthSafe().getContent());
        byte[] content = oct.getOctets();
        byte[] my_digest = this.jSoftLib.mac(macM, macKey, content);
        byte[] digest = digestInfo.getDigest();
        return Parser.isEqualArray(my_digest, digest);
    }

    private void handleCertContent(ContentInfo certContent) throws Exception {
        EncryptedData encryptedData = EncryptedData.getInstance(certContent.getContent());
        EncryptedContentInfo eci = encryptedData.getEncryptedContentInfo();
        PKCS12PBEParams pm = PKCS12PBEParams.getInstance(eci.getContentEncryptionAlgorithm().getParameters());
        byte[] salt = pm.getIV();
        int iterations = pm.getIterations().intValue();
        PKCS12ParametersGenerator p12gen = new PKCS12ParametersGenerator(new SHA1Digest());
        p12gen.init(this.password, salt, iterations);
        ASN1OctetString octetString = eci.getEncryptedContent();
        byte[] en_data = octetString.getOctets();
        byte[] de_data = this.pbeDecrypt(eci.getContentEncryptionAlgorithm().getObjectId().getId(), p12gen, en_data);
        ByteArrayInputStream bis = new ByteArrayInputStream(de_data);
        ASN1InputStream ais = new ASN1InputStream(bis);
        SafeContents safeContents = SafeContents.getInstance((ASN1Sequence)ais.readObject());
        SafeBag[] safeBag = safeContents.getSafeBag();
        Vector v = new Vector();
        ASN1Set set = null;

        for(int i = 0; i < safeBag.length; ++i) {
            if (safeBag[i].getBagId().equals(PKCSObjectIdentifiers.certBag)) {
                CertBag cb = CertBag.getInstance(safeBag[i].getBagValue());
                set = safeBag[i].getBagAttributes();
                v.add(cb);
            }
        }

        this.certBags = new CertBag[v.size()];
        v.toArray(this.certBags);
    }

    private void handleKeyContent(ContentInfo keyContent) throws Exception {
        ASN1OctetString octetString = ASN1OctetString.getInstance(keyContent.getContent());
        ASN1Sequence sequence = this.oct2Seq(octetString);
        SafeContents safeContents = SafeContents.getInstance(sequence);
        SafeBag[] safeBag = safeContents.getSafeBag();
        SafeBag keyBag = safeBag[0];
        if (keyBag.getBagId().equals(PKCSObjectIdentifiers.keyBag)) {
            this.privateKeyInfo = new PrivateKeyInfo((ASN1Sequence)keyBag.getBagValue());
        } else {
            if (!keyBag.getBagId().equals(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag)) {
                throw new Exception("handle keyBag error. bagId = " + keyBag.getBagId().getId());
            }

            EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(Parser.writeDERObj2Bytes(keyBag.getBagValue()));
            AlgorithmParameters algParams = epki.getAlgParameters();

            //oraclejdk :epki.getAlgParameters().getAlgorithm():1.2.840.113549.1.12.1.3
            //openjdk: epki.getAlgParameters().getAlgorithm():PBEWithSHA1AndDESede
            //System.out.println("epki.getAlgParameters().getAlgorithm():"+epki.getAlgParameters().getAlgorithm());

            Class var10001 = null;
            if (var10001 == null) {
                try {
                    var10001 = Class.forName("javax.crypto.spec.PBEParameterSpec");
                } catch (ClassNotFoundException var19) {
                    throw new NoClassDefFoundError(var19.getMessage());
                }

            }

            PBEParameterSpec pbeParamSpec = (PBEParameterSpec)algParams.getParameterSpec(var10001);
            byte[] salt = pbeParamSpec.getSalt();
            int iterations = pbeParamSpec.getIterationCount();
            PKCS12ParametersGenerator p12gen = new PKCS12ParametersGenerator(new SHA1Digest());
            p12gen.init(this.password, salt, iterations);
            byte[] en_data = epki.getEncryptedData();
            byte[] de_data = this.pbeDecrypt(epki.getAlgParameters().getAlgorithm(), p12gen, en_data);
            //byte[] de_data = this.pbeDecrypt("1.2.840.113549.1.12.1.3", p12gen, en_data);
            ByteArrayInputStream bis = new ByteArrayInputStream(de_data);
            ASN1InputStream ais = new ASN1InputStream(bis);
            this.privateKeyInfo = (ASN1Sequence)ais.readObject();
            ASN1Set set = keyBag.getBagAttributes();
            Attribute var18 = Attribute.getInstance(set.getObjectAt(0));
        }

    }

    private byte[] pbeDecrypt(String algName, PKCS12ParametersGenerator p12gen, byte[] en_data) throws Exception {
        CipherParameters param = null;
        Mechanism mechanism = null;
        JKey key = null;
        ParametersWithIV ivParam = null;
        KeyParameter keyParam = null;
        byte[] iv;
        byte[] keyData;
        CBCParam cbcParam;
        if (algName.equals(PKCSObjectIdentifiers.pbeWithSHAAnd3DESCBC.getId()) || "PBEWithSHA1AndDESede".equalsIgnoreCase(algName) ) {
            param = p12gen.generateDerivedParameters(192, 64);
            ivParam = (ParametersWithIV)param;
            iv = ivParam.getIV();
            keyParam = (KeyParameter)ivParam.getParameters();
            keyData = keyParam.getKey();
            key = new JKey("DESede", keyData);
            cbcParam = new CBCParam();
            cbcParam.setIv(iv);
            mechanism = new Mechanism("DESede/CBC/PKCS7Padding", cbcParam);
            return this.jSoftLib.decrypt(mechanism, key, en_data);
        } else if (algName.equals(PKCSObjectIdentifiers.pbeWithSHAAnd2DESCBC.getId())) {
            param = p12gen.generateDerivedParameters(128, 64);
            ivParam = (ParametersWithIV)param;
            iv = ivParam.getIV();
            keyParam = (KeyParameter)ivParam.getParameters();
            keyData = keyParam.getKey();
            key = new JKey("DESede", keyData);
            cbcParam = new CBCParam();
            cbcParam.setIv(iv);
            mechanism = new Mechanism("DESede/CBC/PKCS7Padding", cbcParam);
            return this.jSoftLib.decrypt(mechanism, key, en_data);
        } else if (algName.equals(PKCSObjectIdentifiers.pbeWithSHAAnd128RC2CBC.getId())) {
            param = p12gen.generateDerivedParameters(128, 64);
            return this.rc2doCipher(false, param, en_data);
        } else if (algName.equals(PKCSObjectIdentifiers.pbeWithSHAAnd40RC2CBC.getId())) {
            param = p12gen.generateDerivedParameters(40, 64);
            return this.rc2doCipher(false, param, en_data);
        } else {
            throw new Exception("not support pkcs12pbe algorithm: " + algName);
        }
    }

    public Pfx generatePfx(JKey jprvKey, X509Cert x509cert, char[] _password) throws PKIException {
        X509CertificateStructure cert = x509cert.getCertStructure();
        this.password = PKCS12ParametersGenerator.PKCS12PasswordToBytes(_password);

        try {
            EncryptedPrivateKeyInfo epki = this.generateEPKI(jprvKey);
            DERInteger dint = cert.getSerialNumber();
            byte[] sn = Parser.writeDERObj2Bytes(dint);
            DEROctetString osn = new DEROctetString(sn);
            ASN1EncodableVector derV = new ASN1EncodableVector();
            derV.add(osn);
            DERSet derSet = new DERSet(derV);
            Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, derSet);
            derV = new ASN1EncodableVector();
            derV.add(attribute);
            derSet = new DERSet(derV);
            SafeBag keyBag = new SafeBag(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag, Parser.writeBytes2DERObj(epki.getEncoded()), derSet);
            SafeBag[] keyBags = new SafeBag[]{keyBag};
            SafeContents safeContents = new SafeContents(keyBags);
            DEROctetString octString = new DEROctetString(Parser.writeDERObj2Bytes(safeContents.getDERObject()));
            ContentInfo keyContent = new ContentInfo(PKCSObjectIdentifiers.data, octString);
            ContentInfo[] contentInfos = new ContentInfo[]{keyContent, null};
            octString = new DEROctetString(Parser.writeDERObj2Bytes(cert.getDERObject()));
            CertBag certBag = new CertBag(PKCSObjectIdentifiers.x509certType, octString);
            SafeBag sbag = new SafeBag(PKCSObjectIdentifiers.certBag, certBag.getDERObject(), derSet);
            SafeBag[] certBags = new SafeBag[]{sbag};
            safeContents = new SafeContents(certBags);
            EncryptedData encryptedData = this.encryptedCertContents(safeContents);
            ContentInfo certContent = new ContentInfo(PKCSObjectIdentifiers.encryptedData, encryptedData.getDERObject());
            contentInfos[1] = certContent;
            AuthenticatedSafe authenticatedSafe = new AuthenticatedSafe(contentInfos);
            octString = new DEROctetString(Parser.writeDERObj2Bytes(authenticatedSafe.getDERObject()));
            ContentInfo authSafe = new ContentInfo(PKCSObjectIdentifiers.data, octString);
            MacData macData = this.generateMacData(authSafe);
            return new Pfx(authSafe, macData);
        } catch (Exception var26) {
            throw new PKIException("850609", "产生PKCS12结构失败", var26);
        }
    }

    public Pfx generatePfx(JKey jprvKey, X509Cert[] x509certs, char[] _password) throws PKIException {
        X509CertificateStructure cert = x509certs[0].getCertStructure();
        this.password = PKCS12ParametersGenerator.PKCS12PasswordToBytes(_password);

        try {
            EncryptedPrivateKeyInfo epki = this.generateEPKI(jprvKey);
            DERInteger dint = cert.getSerialNumber();
            byte[] sn = Parser.writeDERObj2Bytes(dint);
            DEROctetString osn = new DEROctetString(sn);
            ASN1EncodableVector derV = new ASN1EncodableVector();
            derV.add(osn);
            DERSet derSet = new DERSet(derV);
            Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, derSet);
            derV = new ASN1EncodableVector();
            derV.add(attribute);
            derSet = new DERSet(derV);
            SafeBag keyBag = new SafeBag(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag, Parser.writeBytes2DERObj(epki.getEncoded()), derSet);
            SafeBag[] keyBags = new SafeBag[]{keyBag};
            SafeContents safeContents = new SafeContents(keyBags);
            DEROctetString octString = new DEROctetString(Parser.writeDERObj2Bytes(safeContents.getDERObject()));
            ContentInfo keyContent = new ContentInfo(PKCSObjectIdentifiers.data, octString);
            ContentInfo[] contentInfos = new ContentInfo[]{keyContent, null};
            CertBag certBag = null;
            SafeBag sbag = null;
            SafeBag[] certBags = new SafeBag[x509certs.length];

            for(int i = 0; i < x509certs.length; ++i) {
                octString = new DEROctetString(Parser.writeDERObj2Bytes(x509certs[i].getCertStructure().getDERObject()));
                certBag = new CertBag(PKCSObjectIdentifiers.x509certType, octString);
                if (i == 0) {
                    sbag = new SafeBag(PKCSObjectIdentifiers.certBag, certBag.getDERObject(), derSet);
                } else {
                    sbag = new SafeBag(PKCSObjectIdentifiers.certBag, certBag.getDERObject());
                }

                certBags[i] = sbag;
            }

            safeContents = new SafeContents(certBags);
            EncryptedData encryptedData = this.encryptedCertContents(safeContents);
            ContentInfo certContent = new ContentInfo(PKCSObjectIdentifiers.encryptedData, encryptedData.getDERObject());
            contentInfos[1] = certContent;
            AuthenticatedSafe authenticatedSafe = new AuthenticatedSafe(contentInfos);
            octString = new DEROctetString(Parser.writeDERObj2Bytes(authenticatedSafe.getDERObject()));
            ContentInfo authSafe = new ContentInfo(PKCSObjectIdentifiers.data, octString);
            MacData macData = this.generateMacData(authSafe);
            return new Pfx(authSafe, macData);
        } catch (Exception var26) {
            throw new PKIException("850609", "产生PKCS12结构失败", var26);
        }
    }

    public void generatePfxFile(JKey jprvKey, X509Cert cert, char[] _password, String fileName) throws PKIException {
        Pfx pfxObj = this.generatePfx(jprvKey, cert, _password);

        try {
            FileOutputStream fos = new FileOutputStream(fileName);
            DEROutputStream dos = new DEROutputStream(fos);
            dos.writeObject(pfxObj);
            dos.close();
            fos.close();
        } catch (Exception var8) {
            throw new PKIException("850609", "产生PKCS12结构失败", var8);
        }
    }

    public void generatePfxFile(JKey jprvKey, X509Cert[] certs, char[] _password, String fileName) throws PKIException {
        Pfx pfxObj = this.generatePfx(jprvKey, certs, _password);

        try {
            FileOutputStream fos = new FileOutputStream(fileName);
            DEROutputStream dos = new DEROutputStream(fos);
            dos.writeObject(pfxObj);
            dos.close();
            fos.close();
        } catch (Exception var8) {
            throw new PKIException("850609", "产生PKCS12结构失败", var8);
        }
    }

    public byte[] generatePfxData(JKey jprvKey, X509Cert cert, char[] _password) throws PKIException {
        Pfx pfxObj = this.generatePfx(jprvKey, cert, _password);
        return Parser.writeDERObj2Bytes(pfxObj.getDERObject());
    }

    public byte[] generatePfxData(JKey jprvKey, X509Cert[] certs, char[] _password) throws PKIException {
        Pfx pfxObj = this.generatePfx(jprvKey, certs, _password);
        return Parser.writeDERObj2Bytes(pfxObj.getDERObject());
    }

    private EncryptedData encryptedCertContents(DEREncodable safeContents) throws Exception {
        SecureRandom sRandom = new SecureRandom();
        byte[] salt = new byte[8];
        sRandom.nextBytes(salt);
        PKCS12ParametersGenerator p12gen = new PKCS12ParametersGenerator(new SHA1Digest());
        p12gen.init(this.password, salt, 2000);
        CipherParameters param = p12gen.generateDerivedParameters(40, 64);
        byte[] en_data = this.rc2doCipher(true, param, Parser.writeDERObj2Bytes(safeContents.getDERObject()));
        DEROctetString octString = new DEROctetString(en_data);
        ASN1EncodableVector vector = new ASN1EncodableVector();
        DEROctetString de0 = new DEROctetString(salt);
        DERInteger deI = new DERInteger(2000);
        vector.add(de0);
        vector.add(deI);
        DERSequence deSeq = new DERSequence(vector);
        AlgorithmIdentifier algId = new AlgorithmIdentifier(PKCSObjectIdentifiers.pbeWithSHAAnd40RC2CBC, deSeq);
        EncryptedContentInfo eci = new EncryptedContentInfo(PKCSObjectIdentifiers.data, algId, octString);
        return new EncryptedData(new DERInteger(0), eci);
    }

    private MacData generateMacData(ContentInfo authSafe) throws Exception {
        SecureRandom sRandom = new SecureRandom();
        byte[] salt = new byte[8];
        sRandom.nextBytes(salt);
        PKCS12ParametersGenerator p12gen = new PKCS12ParametersGenerator(new SHA1Digest());
        p12gen.init(this.password, salt, 2000);
        CipherParameters param = p12gen.generateDerivedMacParameters(160);
        ASN1OctetString oct = ASN1OctetString.getInstance(authSafe.getContent());
        byte[] da = oct.getOctets();
        HMac mac = new HMac(new SHA1Digest());
        mac.init(param);
        mac.update(da, 0, da.length);
        byte[] hmac = new byte[mac.getMacSize()];
        mac.doFinal(hmac, 0);
        DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(new DERObjectIdentifier("1.3.14.3.2.26")), hmac);
        return new MacData(digestInfo, salt, 2000);
    }

    private EncryptedPrivateKeyInfo generateEPKI(JKey prvKey) throws Exception {
        byte[] keyData = prvKey.getKey();
        SecureRandom sRandom = new SecureRandom();
        byte[] salt = new byte[8];
        sRandom.nextBytes(salt);
        PKCS12ParametersGenerator p12gen = new PKCS12ParametersGenerator(new SHA1Digest());
        p12gen.init(this.password, salt, 2000);
        CipherParameters param = p12gen.generateDerivedParameters(192, 64);
        ParametersWithIV ivParam = (ParametersWithIV)param;
        byte[] iv = ivParam.getIV();
        KeyParameter keyParam = (KeyParameter)ivParam.getParameters();
        byte[] encryptKeyData = keyParam.getKey();
        JKey encryptKey = new JKey("DESede", encryptKeyData);
        CBCParam cbcParam = new CBCParam();
        cbcParam.setIv(iv);
        Mechanism mechanism = new Mechanism("DESede/CBC/PKCS7Padding", cbcParam);
        byte[] en_data = this.jSoftLib.encrypt(mechanism, encryptKey, keyData);
        DEROctetString deS = new DEROctetString(en_data);
        ASN1EncodableVector vector = new ASN1EncodableVector();
        DEROctetString de0 = new DEROctetString(salt);
        DERInteger deI = new DERInteger(2000);
        vector.add(de0);
        vector.add(deI);
        DERSequence deSeq = new DERSequence(vector);
        AlgorithmIdentifier algId = new AlgorithmIdentifier(PKCSObjectIdentifiers.pbeWithSHAAnd3DESCBC, deSeq);
        vector = new ASN1EncodableVector();
        vector.add(algId);
        vector.add(deS);
        deSeq = new DERSequence(vector);
        return new EncryptedPrivateKeyInfo(Parser.writeDERObj2Bytes(deSeq));
    }

    private DEREncodable generateRSAPriKeyInfo(CipherParameters param) {
        AlgorithmIdentifier algid = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, (DEREncodable)null);
        RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters)param;
        RSAPrivateKeyStructure RSAPrvStructure = new RSAPrivateKeyStructure(privateKey.getModulus(), privateKey.getPublicExponent(), privateKey.getExponent(), privateKey.getP(), privateKey.getQ(), privateKey.getDP(), privateKey.getDQ(), privateKey.getQInv());
        return new PrivateKeyInfo(algid, RSAPrvStructure.getDERObject());
    }

    public void reset() {
        this.pfx = null;
        this.certBags = null;
        this.privateKeyInfo = null;
        this.keyContent = null;
        this.certContent = null;
        this.password = null;
        this.decrypted = false;
    }

    public Pfx getPfx() {
        return this.pfx;
    }

    private ASN1Sequence oct2Seq(ASN1OctetString oct) throws Exception {
        byte[] b = oct.getOctets();
        ByteArrayInputStream bis = new ByteArrayInputStream(b);
        ASN1InputStream ais = new ASN1InputStream(bis);
        return (ASN1Sequence)ais.readObject();
    }

    private byte[] rc2doCipher(boolean isEncrypt, CipherParameters param, byte[] data) throws Exception {
        BufferedBlockCipher cipher = new PaddedBlockCipher(new CBCBlockCipher(new RC2Engine()));
        cipher.init(isEncrypt, param);
        byte[] out = new byte[cipher.getOutputSize(data.length)];
        int res = cipher.processBytes(data, 0, data.length, out, 0);
        int validLen = -1;
        if (res < out.length) {
            validLen = cipher.doFinal(out, res);
        }

        if (isEncrypt) {
            return out;
        } else {
            byte[] d = new byte[out.length - cipher.getBlockSize() + validLen];
            System.arraycopy(out, 0, d, 0, d.length);
            return d;
        }
    }

    public static void main(String[] args) {
        try {
            JCrypto jcrypto = JCrypto.getInstance();
            jcrypto.initialize("JSOFT_LIB", (Object)null);
            PKCS12 p12 = new PKCS12();
            FileInputStream fin = new FileInputStream("c:/asp.pfx");
            p12.load((InputStream)fin);
            p12.decrypt("111".toCharArray());
            JKey prvKey = p12.getPrivateKey();
            byte[] key = prvKey.getKey();
            X509Cert[] certs = p12.getCerts();
            byte[] pubKey = certs[0].getPublicKey().getKey();
            FileOutputStream fos = new FileOutputStream("c:/test/pubKey");
            fos.write(pubKey);
            fos.close();
            System.out.println(certs.length);
            p12.generatePfxFile(prvKey, certs, "222".toCharArray(), "c:/test/complex.pfx");
            p12.load("c:/test/complex.pfx");
            p12.decrypt("222".toCharArray());
            X509Cert cert = p12.getCertificate();
            fin = new FileInputStream("c:/test/complex.pfx");
            byte[] data = new byte[fin.available()];
            fin.read(data);
            fin.close();
            byte[] b64 = Base64.encode(data);
            fos = new FileOutputStream("c:/test/complex.t");
            fos.write(b64);
            fos.close();
            System.out.println("OK");
        } catch (Exception var13) {
            System.out.println(var13.toString());
        }

    }
}
