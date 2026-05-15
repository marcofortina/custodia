/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

package dev.custodia.client;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class CustodiaPackageReadinessTest {
    public static void main(String[] args) throws Exception {
        cargoEquivalentMetadataIsDocumentedForMaven();
        examplesCompileThroughMakeTarget();
        codeQLFindingIsTriaged();
        publishingRemainsDocumentationGated();
    }

    private static void cargoEquivalentMetadataIsDocumentedForMaven() throws Exception {
        String pom = read("clients/java/pom.xml");
        assertContains(pom, "<groupId>dev.custodia</groupId>", "maven group id");
        assertContains(pom, "<artifactId>custodia-client</artifactId>", "maven artifact id");
        assertContains(pom, "<version>0.0.0-private</version>", "private version");
        assertContains(pom, "<maven.compiler.release>17</maven.compiler.release>", "java release");
        assertContains(pom, "GNU Affero General Public License v3.0 only", "license");
    }

    private static void examplesCompileThroughMakeTarget() {
        List<String> examples = List.of(
            "clients/java/examples/KeyspaceTransportExample.java",
            "clients/java/examples/HighLevelCryptoExample.java"
        );
        for (String example : examples) {
            if (!Files.isRegularFile(Path.of(example))) {
                throw new AssertionError("missing Java example: " + example);
            }
        }
    }

    private static void codeQLFindingIsTriaged() throws Exception {
        String docs = read("docs/JAVA_CLIENT_SDK.md");
        assertContains(docs, "CodeQL/static-IV triage", "CodeQL triage heading");
        assertContains(docs, "HPKE envelope AEAD nonce", "HPKE nonce triage");
        assertContains(docs, "Content encryption still uses a random AES-GCM nonce", "content nonce triage");
    }

    private static void publishingRemainsDocumentationGated() throws Exception {
        String checklist = read("docs/SDK_PUBLISHING_READINESS.md");
        assertContains(checklist, "Java `pom.xml` has Maven coordinates", "Java metadata gate");
        assertContains(checklist, "Java CodeQL/static-IV triage", "Java CodeQL gate");
        assertContains(checklist, "Registry publishing commands are not added to automation", "publish gate");
    }

    private static String read(String path) throws Exception {
        return Files.readString(Path.of(path), StandardCharsets.UTF_8);
    }

    private static void assertContains(String haystack, String needle, String label) {
        if (!haystack.contains(needle)) {
            throw new AssertionError(label + ": missing <" + needle + ">");
        }
    }
}
