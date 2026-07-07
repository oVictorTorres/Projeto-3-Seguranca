package com.example.backend.service.document;

import com.example.backend.domain.DocumentSignature;
import com.example.backend.domain.User;
import com.example.backend.domain.UserKey;
import com.example.backend.dto.document.SignDocumentRequest;
import com.example.backend.dto.document.SignedPdfResult;
import com.example.backend.exception.PdfValidationException;
import com.example.backend.repository.DocumentSignatureRepository;
import com.example.backend.repository.UserKeyRepository;
import com.example.backend.security.UserKeyEncryptionService;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Service
public class PdfSigningService {

    private static final DateTimeFormatter TIMESTAMP_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC);
    private static final float SEAL_WIDTH = 245;
    private static final float SEAL_HEIGHT = 56;
    private static final float SEAL_LEFT_OFFSET = 5;
    private static final float SEAL_TOP_OFFSET = 12;
    private static final float SEAL_BOTTOM_OFFSET = SEAL_HEIGHT - SEAL_TOP_OFFSET;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final PdfValidatorService pdfValidatorService;
    private final UserKeyRepository userKeyRepository;
    private final UserKeyEncryptionService encryptionService;
    private final DocumentSignatureRepository signatureRepository;

    public PdfSigningService(PdfValidatorService pdfValidatorService,
                             UserKeyRepository userKeyRepository,
                             UserKeyEncryptionService encryptionService,
                             DocumentSignatureRepository signatureRepository) {
        this.pdfValidatorService = pdfValidatorService;
        this.userKeyRepository = userKeyRepository;
        this.encryptionService = encryptionService;
        this.signatureRepository = signatureRepository;
    }

    @Transactional
    public SignedPdfResult sign(MultipartFile file,
                                SignDocumentRequest request,
                                User user,
                                String originIp,
                                Instant now) {
        byte[] originalBytes = pdfValidatorService.validateAndRead(file);
        String originalHash = sha256Hex(originalBytes);

        UserKey userKey = userKeyRepository.findByUserId(user.getId())
                .orElseThrow(() -> new IllegalStateException("Par de chaves nao encontrado para o usuario."));

        String privateKeyB64 = encryptionService.decrypt(userKey.getEncryptedPrivateKey());
        PrivateKey privateKey = decodePrivateKey(privateKeyB64, userKey.getKeyAlgorithm());
        PublicKey publicKey = decodePublicKey(userKey.getPublicKey(), userKey.getKeyAlgorithm());

        UUID signatureId = UUID.randomUUID();
        byte[] signedPdfBytes = embedPdfSignature(
                originalBytes, user, originalHash, publicKey, privateKey, userKey.getKeyAlgorithm(),
                signatureId, now, request.sealPage(), request.sealX(), request.sealY());
        String signedHash = sha256Hex(signedPdfBytes);

        DocumentSignature record = DocumentSignature.create(
                user,
                originalHash,
                signedHash,
                signatureId,
                userKey.getKeyAlgorithm(),
                request.sealPage(),
                request.sealX(),
                request.sealY(),
                originIp,
                now
        );
        signatureRepository.save(record);

        return new SignedPdfResult(signedPdfBytes, signatureId, originalHash, signedHash, now);
    }

    private void validateSealPosition(PDPage page, float x, float y) {
        PDRectangle mediaBox = page.getMediaBox();
        if (x < SEAL_LEFT_OFFSET
                || y < SEAL_BOTTOM_OFFSET
                || x - SEAL_LEFT_OFFSET + SEAL_WIDTH > mediaBox.getWidth()
                || y + SEAL_TOP_OFFSET > mediaBox.getHeight()) {
            throw new PdfValidationException("DOC_001", "Posicao do selo invalida.");
        }
    }

    private byte[] embedPdfSignature(byte[] pdfBytes,
                                     User user,
                                     String docHash,
                                     PublicKey publicKey,
                                     PrivateKey privateKey,
                                     String keyAlgorithm,
                                     UUID signatureId,
                                     Instant now,
                                     int sealPage,
                                     BigDecimal sealX,
                                     BigDecimal sealY) {
        try (PDDocument document = Loader.loadPDF(pdfBytes);
             SignatureOptions signatureOptions = visibleSignatureOptions(document, user, docHash, signatureId, now, sealPage, sealX, sealY);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {

            X509Certificate certificate = selfSignedCertificate(user, publicKey, privateKey, keyAlgorithm, now);

            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName(pdfValidatorService.sanitizeText(user.getEmail()));
            signature.setReason("Assinatura digital do documento");
            signature.setContactInfo(PdfVerificationService.SIGNATURE_ID_CONTACT_PREFIX + signatureId);
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(Date.from(now));
            signature.setSignDate(calendar);

            document.addSignature(signature, content -> buildCmsSignature(content, certificate, privateKey, keyAlgorithm), signatureOptions);
            document.saveIncremental(output);
            return output.toByteArray();
        } catch (PdfValidationException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Erro ao assinar o documento.", exception);
        }
    }

    private SignatureOptions visibleSignatureOptions(PDDocument document,
                                                     User user,
                                                     String docHash,
                                                     UUID signatureId,
                                                     Instant now,
                                                     int sealPage,
                                                     BigDecimal sealX,
                                                     BigDecimal sealY)
            throws java.io.IOException {
        int pageIndex = sealPage - 1;
        if (pageIndex < 0 || pageIndex >= document.getNumberOfPages()) {
            throw new PdfValidationException("DOC_001",
                    "Pagina do selo invalida: o PDF possui " + document.getNumberOfPages() + " pagina(s).");
        }

        PDPage page = document.getPage(pageIndex);
        float x = sealX.floatValue();
        float y = sealY.floatValue();
        validateSealPosition(page, x, y);

        float sealLeft = x - SEAL_LEFT_OFFSET;
        float sealBottom = y - SEAL_BOTTOM_OFFSET;
        float topFromPage = page.getMediaBox().getHeight() - sealBottom - SEAL_HEIGHT;
        String signer = pdfValidatorService.sanitizeText(user.getEmail());

        PDVisibleSignDesigner visibleSignDesigner = new PDVisibleSignDesigner(
                document,
                sealImage(signer, docHash, now),
                sealPage
        )
                .signatureFieldName("sig-" + signatureId)
                .coordinates(sealLeft, topFromPage)
                .width(SEAL_WIDTH)
                .height(SEAL_HEIGHT)
                .adjustForRotation();

        PDVisibleSigProperties visibleSignature = new PDVisibleSigProperties()
                .signerName(signer)
                .signatureReason("Assinatura digital do documento")
                .page(sealPage)
                .visualSignEnabled(true)
                .setPdVisibleSignature(visibleSignDesigner);
        visibleSignature.buildSignature();

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPage(pageIndex);
        signatureOptions.setVisualSignature(visibleSignature);
        return signatureOptions;
    }

    private BufferedImage sealImage(String signer, String docHash, Instant now) {
        int width = Math.round(SEAL_WIDTH * 2);
        int height = Math.round(SEAL_HEIGHT * 2);
        float scale = 2f;
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D graphics = image.createGraphics();
        try {
            graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            graphics.scale(scale, scale);

            graphics.setColor(new Color(10, 18, 33));
            graphics.fillRect(0, 0, Math.round(SEAL_WIDTH), Math.round(SEAL_HEIGHT));

            graphics.setColor(new Color(5, 181, 212));
            graphics.setStroke(new BasicStroke(1f));
            graphics.drawRect(0, 0, Math.round(SEAL_WIDTH) - 1, Math.round(SEAL_HEIGHT) - 1);

            drawSealLogo(graphics, 13, 14);

            graphics.setColor(new Color(250, 250, 250));
            graphics.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 7));
            graphics.drawString("Assinado digitalmente", 43, 18);
            graphics.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 6));
            graphics.drawString(signer, 43, 29);

            graphics.setColor(new Color(209, 222, 232));
            graphics.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 6));
            graphics.drawString("UTC " + TIMESTAMP_FMT.format(now), 43, 40);
            graphics.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 5));
            graphics.drawString("SHA-256 " + docHash.substring(0, 24) + "...", 43, 51);
        } finally {
            graphics.dispose();
        }
        return image;
    }

    private void drawSealLogo(Graphics2D graphics, int x, int y) {
        graphics.setColor(new Color(5, 181, 212));
        graphics.fillRect(x, y, 26, 26);

        graphics.setColor(new Color(10, 18, 33));
        graphics.setStroke(new BasicStroke(2.6f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        graphics.drawLine(x + 7, y + 13, x + 12, y + 18);
        graphics.drawLine(x + 12, y + 18, x + 20, y + 8);
    }

    private byte[] buildCmsSignature(InputStream content,
                                     X509Certificate certificate,
                                     PrivateKey privateKey,
                                     String keyAlgorithm) {
        try {
            String signatureAlgorithm = "RSA".equalsIgnoreCase(keyAlgorithm) ? "SHA256withRSA" : "SHA256withECDSA";
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(privateKey);

            CMSTypedData cmsData = new CMSProcessableByteArray(content.readAllBytes());
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build()
            ).build(signer, certificate));
            generator.addCertificates(new JcaCertStore(List.of(certificate)));

            CMSSignedData signedData = generator.generate(cmsData, false);
            return signedData.getEncoded();
        } catch (Exception exception) {
            throw new IllegalStateException("Erro ao gerar assinatura CMS do PDF.", exception);
        }
    }

    private X509Certificate selfSignedCertificate(User user,
                                                  PublicKey publicKey,
                                                  PrivateKey privateKey,
                                                  String keyAlgorithm,
                                                  Instant now) {
        try {
            String signatureAlgorithm = "RSA".equalsIgnoreCase(keyAlgorithm) ? "SHA256withRSA" : "SHA256withECDSA";
            X500Name subject = new X500Name("CN=" + sanitizeCertificateName(user.getEmail()));
            BigInteger serial = new BigInteger(128, SECURE_RANDOM).abs().add(BigInteger.ONE);
            Date notBefore = Date.from(now.minusSeconds(60));
            Date notAfter = Date.from(now.plusSeconds(10L * 365 * 24 * 60 * 60));

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(privateKey);
            X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
                    subject,
                    serial,
                    notBefore,
                    notAfter,
                    subject,
                    publicKey
            ).build(signer);

            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
        } catch (Exception exception) {
            throw new IllegalStateException("Erro ao criar certificado de assinatura do PDF.", exception);
        }
    }

    private String sanitizeCertificateName(String value) {
        String sanitized = pdfValidatorService.sanitizeText(value);
        return sanitized == null || sanitized.isBlank() ? "Usuario" : sanitized.replaceAll("[,=+<>#;\\\\\"]", "");
    }

    private PrivateKey decodePrivateKey(String base64Key, String algorithm) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance(jcaAlgorithm(algorithm)).generatePrivate(spec);
        } catch (Exception exception) {
            throw new IllegalStateException("Erro ao decodificar chave privada.", exception);
        }
    }

    private PublicKey decodePublicKey(String base64Key, String algorithm) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance(jcaAlgorithm(algorithm)).generatePublic(spec);
        } catch (Exception exception) {
            throw new IllegalStateException("Erro ao decodificar chave publica.", exception);
        }
    }

    private String jcaAlgorithm(String algorithm) {
        return "RSA".equalsIgnoreCase(algorithm) ? "RSA" : "EC";
    }

    private String sha256Hex(byte[] data) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
            return HexFormat.of().formatHex(hash);
        } catch (Exception exception) {
            throw new IllegalStateException("Erro ao calcular hash SHA-256.", exception);
        }
    }
}
