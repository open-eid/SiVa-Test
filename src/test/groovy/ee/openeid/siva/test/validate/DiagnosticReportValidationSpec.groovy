/*
 * Copyright 2024 - 2024 Riigi Infosüsteemi Amet
 *
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence")
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the Licence is
 * distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 */

package ee.openeid.siva.test.validate

import ee.openeid.siva.test.DateTimeMatcher
import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import org.hamcrest.Matchers
import org.junit.jupiter.api.Disabled
import spock.lang.Ignore

import java.time.ZoneId
import java.time.ZonedDateTime

import static ee.openeid.siva.test.TestData.*
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.notNullValue

class DiagnosticReportValidationSpec extends GenericSpecification {

    @Description("Diagnostic report includes validationConclusion element")
    def "Given diagnostic report, then it includes validationConclusion element"() {
        expect:
        ZonedDateTime testStartDate = ZonedDateTime.now(ZoneId.of("GMT"))

        SivaRequests.validate(RequestData.validationRequest("ValidLiveSignature.asice", null, ReportType.DIAGNOSTIC))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", equalTo(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", equalTo(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", equalTo(SignaturePolicy.POLICY_4.url))
                .body("signatureForm", equalTo(ContainerFormat.ASiC_E))
                .body("validationTime", DateTimeMatcher.isEqualOrAfter(testStartDate))
                .body("signaturesCount", equalTo(1))
                .body("validSignaturesCount", equalTo(1))
                .body("signatures", notNullValue())
                .body("signatures[0].id", equalTo("S0"))
                .body("signatures[0].signatureFormat", equalTo(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", equalTo(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", equalTo("NURM,AARE,38211015222"))
                .body("signatures[0].indication", equalTo(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signatureScopes[0].name", equalTo("Tresting.txt"))
                .body("signatures[0].signatureScopes[0].scope", equalTo(SIGNATURE_SCOPE_FULL))
                .body("signatures[0].signatureScopes[0].content", equalTo(VALID_SIGNATURE_SCOPE_CONTENT_FULL))
                .body("signatures[0].claimedSigningTime", equalTo("2016-10-11T09:35:48Z"))
                .body("signatures[0].info.bestSignatureTime", equalTo("2016-10-11T09:36:10Z"))
    }

    @Ignore("SIVA-499")
    @Description("Diagnostic report includes tlanalysis element and its values")
    def "Given diagnostic report, then it includes tlanalysis element"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("pades-baseline-lta-live-aj.pdf", null, ReportType.DIAGNOSTIC))
                .then().rootPath(DIAGNOSTIC_DATA_PREFIX)
                .body("signatures[0]", notNullValue())
                .body("signatures[0].signatureFilename", equalTo("pades-baseline-lta-live-aj.pdf"))
                .body("signatures[0].claimedSigningTime", notNullValue())
                .body("signatures[0].signatureFormat", equalTo("PAdES-BASELINE-LTA"))
                .body("signatures[0].contentType", equalTo("1.2.840.113549.1.7.1"))
                .body("signatures[0].structuralValidation.valid", equalTo(true))
                .body("signatures[0].digestMatchers[0].digestMethod", equalTo(HashAlgo.SHA256))
                .body("signatures[0].digestMatchers[0].digestValue", equalTo("7UlS2NYiVo7OhneOHdb6gsTuA1HLM433vrBKSYnI46c="))
                .body("signatures[0].digestMatchers[0].dataFound", equalTo(true))
                .body("signatures[0].digestMatchers[0].dataIntact", equalTo(true))
                .body("signatures[0].digestMatchers[0].type", equalTo("MESSAGE_DIGEST"))
                .body("signatures[0].basicSignature.encryptionAlgoUsedToSignThisToken", equalTo("RSA"))
                .body("signatures[0].basicSignature.keyLengthUsedToSignThisToken", equalTo("2048"))
                .body("signatures[0].basicSignature.digestAlgoUsedToSignThisToken", equalTo(HashAlgo.SHA256))
                .body("signatures[0].basicSignature.signatureIntact", equalTo(true))
                .body("signatures[0].basicSignature.signatureValid", equalTo(true))
                .body("signatures[0].signingCertificate.certificate", equalTo("C-F014C7DF249D8734DF273D937EE5EBF0F8166BE0775C47A80608F1A14EB23F4C"))
                .body("signatures[0].certificateChain.certificate", Matchers.hasItems("C-F014C7DF249D8734DF273D937EE5EBF0F8166BE0775C47A80608F1A14EB23F4C", "C-74D992D3910BCF7E34B8B5CD28F91EAEB4F41F3DA6394D78B8C43672D43F4F0F", "C-3E84BA4342908516E77573C0992F0979CA084E4685681FF195CCBA8A229B8A76"))
                .body("signatures[0].certificateChain.certificate.size()", Matchers.is(3))
                .body("signatures[0].foundTimestamps.timestamp", Matchers.hasItem("T-986BB33B29274A85EF94B7EC0FB89C3427910D59C40A233FD588FBCB2A0E4A84"))
                .body("signatures[0].foundTimestamps.timestamp", Matchers.hasItem("T-180665AC2889F5EEA2FB90E662532A8339672A92671219EFCC87C7C3B9885F7A"))
                .body("signatures[0].signatureScopes[0].signerData", equalTo("D-B8D81DDB95A46D4E2FF6BB1DAA97E0728F6953FDB9BA1F7020F1CDBCEAA20575"))
                .body("signatures[0].signatureScopes[0].description", equalTo("The document ByteRange : [0, 9136, 28082, 26387]"))
                .body("signatures[0].signatureScopes[0].name", equalTo("Partial PDF"))
                .body("signatures[0].signatureScopes[0].scope", equalTo("PARTIAL"))
    }

    @Disabled("SIVA-499")
    @Description("Diagnostic report includes used certificates element and its values")
    def "Given diagnostic report, then it includes certificates element"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("pades-baseline-lta-live-aj.pdf", null, ReportType.DIAGNOSTIC))
                .then().rootPath(DIAGNOSTIC_DATA_PREFIX)
                .body("usedCertificates", notNullValue())
                .body("usedCertificates.serialNumber", notNullValue())
                .body("usedCertificates[2].subjectDistinguishedName.value", Matchers.hasItems("1.2.840.113549.1.9.1=#1609706b6940736b2e6565,cn=sk ocsp responder 2011,ou=ocsp,o=as sertifitseerimiskeskus,l=tallinn,st=harju,c=ee", "1.2.840.113549.1.9.1=#1609706b6940736b2e6565,CN=SK OCSP RESPONDER 2011,OU=OCSP,O=AS Sertifitseerimiskeskus,L=Tallinn,ST=Harju,C=EE"))
                .body("usedCertificates[2].subjectDistinguishedName.value.size()", Matchers.is(2))
                .body("usedCertificates[2].subjectDistinguishedName.format", Matchers.hasItems("CANONICAL", "RFC2253"))
                .body("usedCertificates[2].subjectDistinguishedName.format.size()", Matchers.is(2))
                .body("usedCertificates[2].issuerDistinguishedName.value", Matchers.hasItems("1.2.840.113549.1.9.1=#1609706b6940736b2e6565,cn=ee certification centre root ca,o=as sertifitseerimiskeskus,c=ee", "1.2.840.113549.1.9.1=#1609706b6940736b2e6565,CN=EE Certification Centre Root CA,O=AS Sertifitseerimiskeskus,C=EE"))
                .body("usedCertificates[2].issuerDistinguishedName.value.size()", Matchers.is(2))
                .body("usedCertificates[2].issuerDistinguishedName.format", Matchers.hasItems("CANONICAL", "RFC2253"))
                .body("usedCertificates[2].issuerDistinguishedName.format.size()", Matchers.is(2))
    }

    @Description("Diagnostic report includes wrong signature value")
    def "Given detailed report, then it includes wrong signature value"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TS-02_23634_TS_wrong_SignatureValue.asice", null, ReportType.DIAGNOSTIC))
                .then().rootPath(DIAGNOSTIC_DATA_PREFIX)
                .body("signatures[0].basicSignature.encryptionAlgoUsedToSignThisToken", equalTo("RSA"))
                .body("signatures[0].basicSignature.keyLengthUsedToSignThisToken", equalTo("2048"))
                .body("signatures[0].basicSignature.digestAlgoUsedToSignThisToken", equalTo(HashAlgo.SHA256))
                .body("signatures[0].basicSignature.signatureIntact", equalTo(false))
                .body("signatures[0].basicSignature.signatureValid", equalTo(false))
    }
}
