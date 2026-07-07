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
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockMultipartFile;

import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class PdfSigningServiceTests {

    private static final Instant NOW = Instant.parse("2026-06-08T12:00:00Z");

    private final PdfValidatorService pdfValidatorService = mock(PdfValidatorService.class);
    private final UserKeyRepository userKeyRepository = mock(UserKeyRepository.class);
    private final UserKeyEncryptionService encryptionService = mock(UserKeyEncryptionService.class);
    private final DocumentSignatureRepository signatureRepository = mock(DocumentSignatureRepository.class);
    private final PdfSigningService service = new PdfSigningService(
            pdfValidatorService,
            userKeyRepository,
            encryptionService,
            signatureRepository
    );

    @Test
    void signsValidPdfWithEmbeddedPdfSignatureAndPersistsMetadata() throws Exception {
        byte[] originalPdf = validPdf();
        MockMultipartFile file = pdfFile(originalPdf);
        KeyPair keyPair = rsaKeyPair();
        User user = user();
        UserKey userKey = UserKey.create(
                user,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                "encrypted-private-key",
                "RSA",
                NOW
        );
        when(pdfValidatorService.validateAndRead(file)).thenReturn(originalPdf);
        when(pdfValidatorService.sanitizeText(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(userKeyRepository.findByUserId(user.getId())).thenReturn(Optional.of(userKey));
        when(encryptionService.decrypt("encrypted-private-key"))
                .thenReturn(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));

        SignedPdfResult result = service.sign(
                file,
                request(),
                user,
                "127.0.0.1",
                NOW
        );

        assertThat(result.pdfBytes()).startsWith("%PDF-".getBytes());
        assertThat(result.originalHash()).isEqualTo(sha256Hex(originalPdf));
        assertThat(result.signedHash()).isEqualTo(sha256Hex(result.pdfBytes()));
        assertThat(result.originalHash()).isNotEqualTo(result.signedHash());
        assertThat(result.signedAt()).isEqualTo(NOW);

        try (PDDocument signedDocument = Loader.loadPDF(result.pdfBytes())) {
            assertThat(signedDocument.getSignatureDictionaries()).hasSize(1);
            PDSignature signature = signedDocument.getSignatureDictionaries().getFirst();
            assertThat(signature.getFilter()).isEqualTo(PDSignature.FILTER_ADOBE_PPKLITE.getName());
            assertThat(signature.getSubFilter()).isEqualTo(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED.getName());
            assertThat(signature.getContents(result.pdfBytes())).isNotEmpty();
            assertThat(signedDocument.getPage(0).getAnnotations())
                    .extracting(PDAnnotation::getAppearance)
                    .anySatisfy(appearance -> assertThat(appearance.getNormalAppearance()).isNotNull());
        }

        ArgumentCaptor<DocumentSignature> captor = ArgumentCaptor.forClass(DocumentSignature.class);
        verify(signatureRepository).save(captor.capture());
        DocumentSignature saved = captor.getValue();
        assertThat(saved.getUser()).isSameAs(user);
        assertThat(saved.getOriginalHash()).isEqualTo(result.originalHash());
        assertThat(saved.getSignedHash()).isEqualTo(result.signedHash());
        assertThat(saved.getSignatureId()).isEqualTo(result.signatureId());
        assertThat(saved.getKeyAlgorithm()).isEqualTo("RSA");
        assertThat(saved.getSealPage()).isEqualTo(1);
        assertThat(saved.getSealX()).isEqualByComparingTo(BigDecimal.valueOf(80));
        assertThat(saved.getSealY()).isEqualByComparingTo(BigDecimal.valueOf(150));
        assertThat(saved.getOriginIp()).isEqualTo("127.0.0.1");
        assertThat(saved.getSignedAt()).isEqualTo(NOW);
    }

    @Test
    void invalidPdfStopsBeforeKeyAccessAndSignatureRecord() {
        MockMultipartFile file = pdfFile(new byte[0]);
        when(pdfValidatorService.validateAndRead(file))
                .thenThrow(new PdfValidationException("DOC_001", "Documento PDF invalido."));

        assertThatThrownBy(() -> service.sign(file, request(), user(), "127.0.0.1", NOW))
                .isInstanceOf(PdfValidationException.class)
                .hasMessage("Documento PDF invalido.");

        verify(pdfValidatorService).validateAndRead(file);
        verify(userKeyRepository, never()).findByUserId(any());
        verifyNoInteractions(encryptionService);
        verifyNoInteractions(signatureRepository);
    }

    @Test
    void signatureFailureDoesNotPersistMetadata() throws Exception {
        byte[] originalPdf = validPdf();
        MockMultipartFile file = pdfFile(originalPdf);
        KeyPair keyPair = rsaKeyPair();
        User user = user();
        UserKey userKey = UserKey.create(
                user,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                "encrypted-private-key",
                "RSA",
                NOW
        );
        when(pdfValidatorService.validateAndRead(file)).thenReturn(originalPdf);
        when(pdfValidatorService.sanitizeText(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(userKeyRepository.findByUserId(user.getId())).thenReturn(Optional.of(userKey));
        when(encryptionService.decrypt("encrypted-private-key")).thenReturn("not-base64-private-key");

        assertThatThrownBy(() -> service.sign(file, request(), user, "127.0.0.1", NOW))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Erro ao decodificar chave privada.");

        verify(signatureRepository, never()).save(any());
    }

    @Test
    void invalidSealPageDoesNotPersistMetadata() throws Exception {
        byte[] originalPdf = validPdf();
        MockMultipartFile file = pdfFile(originalPdf);
        KeyPair keyPair = rsaKeyPair();
        User user = user();
        UserKey userKey = UserKey.create(
                user,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                "encrypted-private-key",
                "RSA",
                NOW
        );
        when(pdfValidatorService.validateAndRead(file)).thenReturn(originalPdf);
        when(pdfValidatorService.sanitizeText(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(userKeyRepository.findByUserId(user.getId())).thenReturn(Optional.of(userKey));
        when(encryptionService.decrypt("encrypted-private-key"))
                .thenReturn(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));

        assertThatThrownBy(() -> service.sign(
                file,
                new SignDocumentRequest(2, BigDecimal.valueOf(80), BigDecimal.valueOf(150)),
                user,
                "127.0.0.1",
                NOW
        ))
                .isInstanceOf(PdfValidationException.class)
                .hasMessage("Pagina do selo invalida: o PDF possui 1 pagina(s).");

        verify(signatureRepository, never()).save(any());
    }

    private SignDocumentRequest request() {
        return new SignDocumentRequest(1, BigDecimal.valueOf(80), BigDecimal.valueOf(150));
    }

    private MockMultipartFile pdfFile(byte[] bytes) {
        return new MockMultipartFile("file", "document.pdf", "application/pdf", bytes);
    }

    private byte[] validPdf() throws Exception {
        try (PDDocument document = new PDDocument();
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            document.addPage(new PDPage());
            document.save(output);
            return output.toByteArray();
        }
    }

    private KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private User user() {
        return User.register(
                UUID.fromString("11111111-1111-1111-1111-111111111111"),
                "user@example.com",
                "password-hash",
                NOW
        );
    }

    private String sha256Hex(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
