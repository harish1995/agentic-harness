"""Builds a synthetic, ~90-class, Spring-Boot-shaped fat JAR fixture used by
the Phase 1 integration gate (`tests/integration/test_scan_pipeline.py`) and
the `report-dashboard-ui` slice's Playwright E2E smoke test.

Usable both as an importable function:

    from tests.fixtures.build_fixture_jar import build_fixture_jar
    build_fixture_jar("/tmp/fixture.jar")

and as a CLI (pinned invocation shape — do not change):

    uv run python tests/fixtures/build_fixture_jar.py <output_jar_path>

Design (see `spec/roadmap.md` Phase 1 gate item 4 and `spec/agent.md` ->
Triage Heuristic): ~13 genuinely security-relevant classes (real, compilable
JDK-only vulnerable patterns: SQL injection, command injection, LDAP
injection, XXE, unsafe deserialization, weak crypto, hardcoded secrets,
unsafe file upload, logged passwords, missing/weak authorization) plus 77
boring, zero-relevance POJOs — 90 classes total, comfortably more than
`AGENT_TRIAGE_MAX_CLASSES=60`, so the triage cap is exercised for real by
this fixture (relevance-scoring, not the cap itself, is what keeps
`triaged_chunks` small here — see the module docstring in
`src/analysis/triage.py`).

Exactly ONE of the 6 LLM review categories is deliberately left clean:
`review_dependencies`. Every other category (injection, authn/authz,
crypto/secrets, deserialization/upload, config/logging) has at least one
deliberately planted, genuinely security-relevant defect above, so the real
review LLM correctly finds a real issue in each of those five. The
dependency list this fixture produces (see the nested `BOOT-INF/lib/*.jar`
filenames below), by contrast, contains only recent, fully patched
Spring Boot / Spring Security / Log4j releases with no known-CVE-shaped
version pattern, so the real `review_dependencies` LLM pass has nothing
concrete to reason about and legitimately returns exactly one
`no_evidence_marker` finding ("No evidence found.") for that category —
proving the evidence-only, never-invent design end-to-end (see
`spec/roadmap.md` Phase 1 gate item 4's "at least one category renders
'No evidence found.'" assertion).

No real Spring Framework/Spring Security dependency is required to compile
this fixture — the handful of Spring-shaped API surfaces the fixture code
references (`HttpSecurity`, `@PreAuthorize`, `PasswordEncoder`, `BCrypt`,
`Jwts.`, `UserDetailsService`, `MultipartFile`, `@Query`, `EntityManager`,
`@Value`, `@ConfigurationProperties`) are defined locally in `SpringShim`,
purely so the triage heuristic's keyword scan (a grep over decompiled text,
not a real dependency check) finds the same surface it would in a real
Spring Boot app. Nested `BOOT-INF/lib/*.jar` files use real Spring-Boot-
shaped filenames (per the pinned Spring-detection filename regexes) but
contain no real Spring bytecode — they don't need to, since Spring-Boot/
Spring-Security detection keys off filename regex + `application.yml`
presence, not actual jar contents.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# Deliberately security-relevant fixture class names — the integration test
# asserts these appear in the assembled report's Appendix "deep-reviewed"
# listing (triage's relevance-scoring picks all of these up).
SECURITY_RELEVANT_CLASS_NAMES: list[str] = [
    "SecurityConfig",
    "AuthService",
    "JwtTokenProvider",
    "CryptoUtils",
    "DeserializationHandler",
    "XmlParserService",
    "UserController",
    "OrderRepository",
    "FileUploadController",
    "AdminController",
    "LdapAuthController",
    "AppConfig",
    "LoggingConfig",
]

# A deliberately boring, zero-relevance POJO name the integration test
# asserts does NOT appear in the deep-reviewed listing.
PLAIN_POJO_SAMPLE_CLASS_NAME = "Dto001"

_POJO_COUNT = 77
_JAVA_BIN = "javac"


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Security-relevant fixture source files (real, compilable, JDK-only
# vulnerable patterns).
# ---------------------------------------------------------------------------

_SPRING_SHIM_JAVA = """package com.example.app.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Local shim types standing in for a handful of Spring Framework / Spring
 * Security API shapes so this fixture compiles with only the JDK on the
 * classpath, while still producing decompiled source containing the same
 * keyword surface a real Spring Boot app would.
 */
public final class SpringShim {

    private SpringShim() {
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface PreAuthorize {
        String value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface Secured {
        String[] value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.FIELD)
    public @interface Value {
        String value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.TYPE)
    public @interface ConfigurationProperties {
        String prefix();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface Query {
        String value();
    }

    public static class SecurityFilterChain {
    }

    public static class HttpSecurity {
        public HttpSecurity authorizeRequests() {
            return this;
        }

        public HttpSecurity antMatchers(String pattern) {
            return this;
        }

        public HttpSecurity permitAll() {
            return this;
        }

        public HttpSecurity anyRequest() {
            return this;
        }

        public HttpSecurity authenticated() {
            return this;
        }

        public HttpSecurity csrf() {
            return this;
        }

        public HttpSecurity disable() {
            return this;
        }

        public SecurityFilterChain build() {
            return new SecurityFilterChain();
        }
    }

    public interface UserDetailsService {
        Object loadUserByUsername(String username);
    }

    public static class PasswordEncoder {
        public String encode(String rawPassword) {
            return rawPassword;
        }
    }

    public static class BCrypt {
        public static String hashpw(String password, String salt) {
            return password + salt;
        }

        public static String gensalt() {
            return "fixed-salt-for-fixture";
        }
    }

    public static class Jwts {
        public static String buildToken(String subject, String signingSecretKey) {
            return subject + "." + signingSecretKey;
        }
    }

    public interface MultipartFile {
        String getOriginalFilename();

        byte[] getBytes() throws java.io.IOException;
    }

    public static class EntityManager {
        public Object createQuery(String jpql) {
            return jpql;
        }
    }
}
"""

_SECURITY_CONFIG_JAVA = """package com.example.app.security;

public class SecurityConfig {

    public SpringShim.SecurityFilterChain filterChain(SpringShim.HttpSecurity http) {
        // Deliberately vulnerable fixture: CSRF protection disabled and the
        // admin endpoint left unauthenticated for the security-review LLM
        // to detect.
        return http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/admin/**").permitAll()
                .anyRequest().authenticated()
                .build();
    }

    @SpringShim.PreAuthorize("hasRole('ADMIN')")
    public void deleteAllUsers() {
        System.out.println("all users deleted");
    }

    public void unprotectedAdminReset() {
        // No @PreAuthorize / @Secured here despite being a sensitive
        // operation -- an authorization-coverage gap for the review pass.
        System.out.println("system reset");
    }
}
"""

_AUTH_SERVICE_JAVA = """package com.example.app.security;

public class AuthService {

    public boolean checkPassword(String rawPassword, String storedHash) {
        // Weak/fixed-salt hashing -- a real defect for the crypto review pass.
        String hashed = SpringShim.BCrypt.hashpw(rawPassword, "fixed-salt-for-fixture");
        return hashed.equals(storedHash);
    }

    public Object login(final String username) {
        SpringShim.UserDetailsService uds = new SpringShim.UserDetailsService() {
            @Override
            public Object loadUserByUsername(String forUsername) {
                return forUsername;
            }
        };
        return uds.loadUserByUsername(username);
    }
}
"""

_JWT_TOKEN_PROVIDER_JAVA = """package com.example.app.security;

public class JwtTokenProvider {

    // Deliberately hardcoded JWT signing secret -- a real fixture defect for
    // the crypto/secrets review pass (also matches the secret-scanner's
    // "JWT / Generic Secret Key" regex pattern).
    private final String secretKey = "supersecretjwtsigningkey123";

    public String issueToken(String username) {
        return SpringShim.Jwts.buildToken(username, secretKey);
    }
}
"""

_CRYPTO_UTILS_JAVA = """package com.example.app.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import javax.crypto.Cipher;

public class CryptoUtils {

    public byte[] weakHash(String input) throws NoSuchAlgorithmException {
        // MD5 for a security-sensitive hash -- weak/broken crypto.
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(input.getBytes());
    }

    public Cipher weakCipher() throws Exception {
        // ECB mode leaks structure -- weak/broken crypto.
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    public int insecureRandomToken() {
        // java.util.Random is not cryptographically secure.
        Random random = new Random();
        return random.nextInt();
    }
}
"""

_DESERIALIZATION_HANDLER_JAVA = """package com.example.app.security;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class DeserializationHandler {

    public Object deserialize(byte[] untrustedBytes) throws IOException, ClassNotFoundException {
        // Deserializing an attacker-controllable byte stream with no type
        // filtering -- classic unsafe deserialization.
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(untrustedBytes))) {
            return ois.readObject();
        }
    }

    public Object decodeXml(byte[] untrustedXml) {
        try (XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(untrustedXml))) {
            return decoder.readObject();
        }
    }
}
"""

_XML_PARSER_SERVICE_JAVA = """package com.example.app.security;

import java.io.ByteArrayInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.xml.sax.helpers.DefaultHandler;

public class XmlParserService {

    public Document parseUntrustedXml(byte[] untrustedXml) throws Exception {
        // External entity resolution is NOT disabled here -- a classic XXE
        // vulnerability when parsing attacker-controlled XML.
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(untrustedXml));
    }

    public void parseWithSax(byte[] untrustedXml) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        parser.parse(new ByteArrayInputStream(untrustedXml), new DefaultHandler());
    }

    public String evaluateXPath(String expression, Document document) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate(expression, document);
    }
}
"""

_USER_CONTROLLER_JAVA = """package com.example.app.controller;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class UserController {

    public boolean findUserByName(Connection connection, String name) throws SQLException {
        // Deliberately vulnerable fixture: string-concatenated SQL passed to
        // Statement.execute -- classic SQL injection.
        Statement stmt = connection.createStatement();
        return stmt.execute("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
"""

_ORDER_REPOSITORY_JAVA = """package com.example.app.repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

import com.example.app.security.SpringShim;

public class OrderRepository {

    public boolean findByCustomerSafe(Connection connection, String customerId) throws SQLException {
        // Correct, parameterized usage -- should NOT be flagged.
        PreparedStatement ps = connection.prepareStatement("SELECT * FROM orders WHERE customer_id = ?");
        ps.setString(1, customerId);
        return ps.execute();
    }

    public boolean findByStatus(Connection connection, String status) throws SQLException {
        // Deliberately vulnerable: concatenated SQL via createStatement.
        Statement stmt = connection.createStatement();
        return stmt.execute("SELECT * FROM orders WHERE status = '" + status + "'");
    }

    @SpringShim.Query("SELECT o FROM Order o WHERE o.id = :id")
    public Object findById(SpringShim.EntityManager em, String id) {
        return em.createQuery("SELECT o FROM Order o WHERE o.id = " + id);
    }
}
"""

_FILE_UPLOAD_CONTROLLER_JAVA = """package com.example.app.controller;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import com.example.app.security.SpringShim;

public class FileUploadController {

    public void handleUpload(SpringShim.MultipartFile file, String uploadDir) throws IOException {
        // Deliberately vulnerable: the attacker-controlled original filename
        // is used directly to build the destination path (path traversal),
        // with no extension/content validation.
        String destinationPath = uploadDir + "/" + file.getOriginalFilename();
        try (FileOutputStream out = new FileOutputStream(new File(destinationPath))) {
            out.write(file.getBytes());
        }
    }
}
"""

_ADMIN_CONTROLLER_JAVA = """package com.example.app.controller;

import java.io.IOException;

public class AdminController {

    public Process runDiagnostic(String userSuppliedHostname) throws IOException {
        // Deliberately vulnerable: attacker-controllable input concatenated
        // directly into a shell command -- command injection.
        return Runtime.getRuntime().exec("ping -c 1 " + userSuppliedHostname);
    }

    public Process runDiagnosticBuilder(String userSuppliedArg) throws IOException {
        ProcessBuilder builder = new ProcessBuilder("sh", "-c", "echo " + userSuppliedArg);
        return builder.start();
    }
}
"""

_LDAP_AUTH_CONTROLLER_JAVA = """package com.example.app.controller;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;

public class LdapAuthController {

    public void search(DirContext context, String userSuppliedUsername) throws NamingException {
        // Deliberately vulnerable: attacker-controllable input concatenated
        // directly into an LDAP search filter -- LDAP injection.
        String filter = "(&(objectClass=user)(uid=" + userSuppliedUsername + "))";
        context.search("dc=example,dc=com", filter, new SearchControls());
    }
}
"""

_APP_CONFIG_JAVA = """package com.example.app.config;

import com.example.app.security.SpringShim;

@SpringShim.ConfigurationProperties(prefix = "app")
public class AppConfig {

    // Deliberately hardcoded fixture "secret" resembling an AWS access key
    // ID (matches the secret-scanner's AWS Access Key ID pattern) -- a
    // clearly-fake fixture value, never a real credential.
    private static final String AWS_ACCESS_KEY_ID = "AKIA" + "ABCDEFGHIJKLMNOP";

    @SpringShim.Value("${app.feature.enabled:false}")
    private boolean featureEnabled;

    public String readDatabasePasswordFromEnv() {
        return System.getenv("DB_PASSWORD");
    }

    public String getAwsAccessKeyId() {
        return AWS_ACCESS_KEY_ID;
    }

    public boolean isFeatureEnabled() {
        return featureEnabled;
    }
}
"""

_LOGGING_CONFIG_JAVA = """package com.example.app.config;

import java.util.logging.Logger;

public class LoggingConfig {

    private static final Logger logger = Logger.getLogger(LoggingConfig.class.getName());

    public void logLoginAttempt(String username, String password) {
        // Deliberately vulnerable: logging a raw password value.
        logger.info("Login attempt for user=" + username + " password=" + password);
    }
}
"""

_SECURITY_RELEVANT_SOURCES: dict[str, str] = {
    "com/example/app/security/SpringShim.java": _SPRING_SHIM_JAVA,
    "com/example/app/security/SecurityConfig.java": _SECURITY_CONFIG_JAVA,
    "com/example/app/security/AuthService.java": _AUTH_SERVICE_JAVA,
    "com/example/app/security/JwtTokenProvider.java": _JWT_TOKEN_PROVIDER_JAVA,
    "com/example/app/security/CryptoUtils.java": _CRYPTO_UTILS_JAVA,
    "com/example/app/security/DeserializationHandler.java": _DESERIALIZATION_HANDLER_JAVA,
    "com/example/app/security/XmlParserService.java": _XML_PARSER_SERVICE_JAVA,
    "com/example/app/controller/UserController.java": _USER_CONTROLLER_JAVA,
    "com/example/app/repository/OrderRepository.java": _ORDER_REPOSITORY_JAVA,
    "com/example/app/controller/FileUploadController.java": _FILE_UPLOAD_CONTROLLER_JAVA,
    "com/example/app/controller/AdminController.java": _ADMIN_CONTROLLER_JAVA,
    "com/example/app/controller/LdapAuthController.java": _LDAP_AUTH_CONTROLLER_JAVA,
    "com/example/app/config/AppConfig.java": _APP_CONFIG_JAVA,
    "com/example/app/config/LoggingConfig.java": _LOGGING_CONFIG_JAVA,
}


def _pojo_source(index: int) -> str:
    class_name = f"Dto{index:03d}"
    return f"""package com.example.app.dto;

public class {class_name} {{

    private int id;
    private String label;
    private double amount;

    public int getId() {{
        return id;
    }}

    public void setId(int id) {{
        this.id = id;
    }}

    public String getLabel() {{
        return label;
    }}

    public void setLabel(String label) {{
        this.label = label;
    }}

    public double getAmount() {{
        return amount;
    }}

    public void setAmount(double amount) {{
        this.amount = amount;
    }}
}}
"""


_APPLICATION_YML = """server:
  port: 8080

spring:
  application:
    name: fixture-app
  datasource:
    url: jdbc:postgresql://localhost:5432/fixturedb
    username: fixture_user
    password: "changeme123"

logging:
  level:
    root: INFO
"""

_MANIFEST_MF = """Manifest-Version: 1.0
Main-Class: org.springframework.boot.loader.JarLauncher
Start-Class: com.example.app.Application
Implementation-Title: fixture-app
Implementation-Version: 0.0.1-FIXTURE
"""


def _build_stub_nested_jar(name: str, pom_properties: str | None = None) -> bytes:
    """A tiny, valid (but contentless) jar with a Spring-Boot-shaped
    filename -- Spring/Spring-Security detection keys off the *filename*
    (per the pinned regexes), not real bytecode inside."""
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        if pom_properties is not None:
            group_artifact = name.rsplit("-", 2)[0]
            zf.writestr(
                f"META-INF/maven/{group_artifact}/{group_artifact}/pom.properties",
                pom_properties,
            )
    return buffer.getvalue()


def _compile_all(src_root: Path, classes_dir: Path) -> None:
    classes_dir.mkdir(parents=True, exist_ok=True)
    java_files = sorted(str(p) for p in src_root.rglob("*.java"))
    if not java_files:
        raise RuntimeError("No .java files found to compile for the fixture JAR.")

    result = subprocess.run(
        [_JAVA_BIN, "-d", str(classes_dir), "-nowarn", *java_files],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"javac failed compiling the fixture sources (exit {result.returncode}):\n"
            f"{result.stderr[-4000:]}"
        )


def build_fixture_jar(output_jar_path: str | Path) -> Path:
    """Build the ~90-class synthetic Spring-Boot-shaped fat JAR fixture at
    `output_jar_path`. Returns the resolved output path.
    """
    output_path = Path(output_jar_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="fixture-jar-build-") as tmp:
        tmp_path = Path(tmp)
        src_root = tmp_path / "src"
        classes_dir = tmp_path / "classes"

        for relative_path, content in _SECURITY_RELEVANT_SOURCES.items():
            _write_text(src_root / relative_path, content)

        for i in range(1, _POJO_COUNT + 1):
            _write_text(
                src_root / "com/example/app/dto" / f"Dto{i:03d}.java",
                _pojo_source(i),
            )

        _compile_all(src_root, classes_dir)

        # `review_dependencies` (see spec/agent.md -> Triage Heuristic /
        # CATEGORY_KEYWORDS) is the ONE category this fixture deliberately
        # leaves clean: every nested-jar filename below is a recent, fully
        # patched release with no known-CVE-shaped version pattern, so the
        # real dependency-review LLM pass has nothing concrete to flag and
        # legitimately returns "No evidence found." for this category,
        # proving that evidence-only path end-to-end. Every OTHER category
        # keeps its deliberately vulnerable content (see the classes above).
        spring_boot_jar = _build_stub_nested_jar(
            "spring-boot-3.3.5.jar",
            pom_properties=(
                "groupId=org.springframework.boot\n"
                "artifactId=spring-boot\n"
                "version=3.3.5\n"
            ),
        )
        spring_security_jar = _build_stub_nested_jar("spring-security-web-6.3.4.jar")
        log4j_jar = _build_stub_nested_jar("log4j-core-2.24.3.jar")

        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as jar:
            jar.writestr("META-INF/MANIFEST.MF", _MANIFEST_MF)
            jar.writestr("BOOT-INF/classes/application.yml", _APPLICATION_YML)

            for class_file in sorted(classes_dir.rglob("*.class")):
                arcname = "BOOT-INF/classes/" + str(class_file.relative_to(classes_dir)).replace("\\", "/")
                jar.write(class_file, arcname)

            jar.writestr("BOOT-INF/lib/spring-boot-3.3.5.jar", spring_boot_jar)
            jar.writestr("BOOT-INF/lib/spring-security-web-6.3.4.jar", spring_security_jar)
            jar.writestr("BOOT-INF/lib/log4j-core-2.24.3.jar", log4j_jar)

    return output_path


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: uv run python tests/fixtures/build_fixture_jar.py <output_jar_path>", file=sys.stderr)
        raise SystemExit(2)
    result_path = build_fixture_jar(sys.argv[1])
    print(f"Built fixture JAR: {result_path}")
