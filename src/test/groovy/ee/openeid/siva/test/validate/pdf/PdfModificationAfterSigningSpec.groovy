/*
 * Copyright 2026 Riigi Infosüsteemi Amet
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

package ee.openeid.siva.test.validate.pdf

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.*
import io.restassured.response.Response

import static ee.openeid.siva.test.TestData.*
import static org.hamcrest.Matchers.*

@Epic("Signature validation (datafile)")
@Feature("PDF validation")
@Link("https://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#common_POLv3_POLv4")
class PdfModificationAfterSigningSpec extends GenericSpecification {

    @Story("Unmodified PDF validates without modification warnings")
    def "Unmodified PAdES LT signature (#description) validates without modification warnings"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(file))

        then: "signature passes without warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LT))
                .body("signatures[0].signatureLevel", is(SignatureLevel.QESIG))
                .body("signatures[0].signedBy", is(signedBy))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))

        where:
        description                         | file                               | signedBy
        "invisible signature"               | "00-base-signed-LT.pdf"            | "MÖLDER,HUGO MARTIN,38910239121"
        "visible signature"                 | "50-visible-signature.pdf"         | "JÕEORG,JAAK-KRISTJAN,38001085718"
        "certifying signature DocMDP P=1"   | "20-docmdp-P1-signed.pdf"          | "MÖLDER,HUGO MARTIN,38910239121"
        "certifying signature DocMDP P=2"   | "30-docmdp-P2-signed.pdf"          | "MÖLDER,HUGO MARTIN,38910239121"
        "signature with FieldMDP lock"      | "40-fieldmdp-signed.pdf"           | "MÖLDER,HUGO MARTIN,38910239121"
        "annotation present before signing" | "60-annotation-before-signing.pdf" | "JÕEORG,JAAK-KRISTJAN,38001085718"
        "eleven page document"              | "80-eleven-pages-signed-LT.pdf"    | "JÕEORG,JAAK-KRISTJAN,38001085718"
    }

    @Story("Change in signed byte range invalidates signature")
    def "Byte modified inside signed byte range fails signature with hash failure"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest("10-signed-range-byte-modified.pdf"))

        then: "signature fails with hash failure"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("signatures[0].subIndication", is(SUB_INDICATION_HASH_FAILURE))
                .body("signatures[0].errors.content", contains(REFERENCE_DATA_NOT_INTACT))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(1))
    }

    @Story("Permitted change after signing keeps signature valid")
    def "Permitted change after signing (#description) keeps signature valid without warnings"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(file))

        then: "signature passes without warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))

        where:
        description                          | file
        "form field filled"                  | "06-form-filled.pdf"
        "metadata changed"                   | "07-metadata-changed.pdf"
        "bytes appended after EOF"           | "09-bytes-after-eof.pdf"
        "form field filled under DocMDP P=2" | "31-docmdp-P2-form-filled-allowed.pdf"
    }

    @Story("Permitted change keeps signature valid under POLv3")
    def "Permitted change under POLv3 policy (#description) keeps signature valid without warnings"() {
        when: "validation is requested with POLv3 policy"
        Response response = SivaRequests.validate(RequestData.validationRequest(file, SignaturePolicy.POLICY_3))

        then: "signature passes without warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))

        where:
        description           | file
        "unmodified document" | "00-base-signed-LT.pdf"
        "form field filled"   | "06-form-filled.pdf"
    }

    @Story("Permitted change after document timestamp keeps signature valid")
    def "PAdES LTA signature (#description) validates without modification warnings"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(file))

        then: "LTA signature passes without warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LTA))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))

        where:
        description                                  | file
        "unmodified after document timestamp"        | "70-base-signed-LTA.pdf"
        "form field filled after document timestamp" | "75-lta-form-filled.pdf"
    }

    @Story("Page count change after signing produces warnings")
    def "Page #description is reported as warnings on every signature"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(file))

        then: "every signature passes with warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures.indication", everyItem(is(SignatureIndication.TOTAL_PASSED)))
                .body("signatures.warnings.content", everyItem(containsInAnyOrder(
                        PDF_PAGE_COUNT_MISMATCH,
                        PDF_ANNOTATION_CHANGES,
                        PDF_UNDEFINED_CHANGES)))
                .body("validSignaturesCount", is(signatures))
                .body("signaturesCount", is(signatures))

        where:
        description                      | file                                     | signatures
        "added after signing"            | "03-page-added.pdf"                      | 1
        "removed after signing"          | "04-page-removed.pdf"                    | 1
        "added after both co-signatures" | "K01-cosigned-page-added-after-both.pdf" | 2
    }

    @Story("Content change after signing produces warnings")
    def "Content change after signing (#description) is reported as warnings"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(file))

        then: "signature passes with content change warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings.content", containsInAnyOrder(*warnings))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))

        where:
        description                               | file                                  | warnings
        "content overlaid"                        | "01-content-overlay.pdf"              | [PDF_VISUAL_DIFFERENCE + "[1]", PDF_UNDEFINED_CHANGES]
        "content replaced"                        | "02-content-replaced.pdf"             | [PDF_VISUAL_DIFFERENCE + "[1]", PDF_UNDEFINED_CHANGES]
        "page order changed"                      | "08-page-order-changed.pdf"           | [PDF_VISUAL_DIFFERENCE + "[1, 2]", PDF_UNDEFINED_CHANGES, PDF_ANNOTATION_CHANGES]
        "content overlaid under FieldMDP"         | "42-fieldmdp-content-overlay.pdf"     | [PDF_VISUAL_DIFFERENCE + "[1]", PDF_UNDEFINED_CHANGES]
        "locked form field filled under FieldMDP" | "43-fieldmdp-locked-field-filled.pdf" | [PDF_VISUAL_DIFFERENCE + "[1]", PDF_UNDEFINED_CHANGES]
        "existing annotation modified in place"   | "61-annotation-modified.pdf"          | [PDF_VISUAL_DIFFERENCE + "[1]", PDF_UNDEFINED_CHANGES]
    }

    @Story("Annotation change after signing produces warnings")
    def "Annotation change after signing (#description) is reported as warnings on every signature"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(file))

        then: "every signature passes with annotation change warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures.indication", everyItem(is(SignatureIndication.TOTAL_PASSED)))
                .body("signatures.warnings.content", everyItem(containsInAnyOrder(*warnings)))
                .body("validSignaturesCount", is(signatures))
                .body("signaturesCount", is(signatures))

        where:
        description                                     | file                                       | signatures | warnings
        "annotation over page content"                  | "05-annotation-overlay.pdf"                | 1          | [PDF_ANNOTATION_CHANGES]
        "annotation over form field"                    | "11-annotation-over-form-field.pdf"        | 1          | [PDF_ANNOTATION_CHANGES, PDF_ELEMENTS_OVERLAP + "[1]"]
        "existing annotation deleted"                   | "62-annotation-deleted.pdf"                | 1          | [PDF_ANNOTATION_CHANGES, PDF_VISUAL_DIFFERENCE + "[1]"]
        "existing annotation replaced"                  | "63-annotation-replaced.pdf"               | 1          | [PDF_ANNOTATION_CHANGES, PDF_VISUAL_DIFFERENCE + "[1]"]
        "annotation added after two visible signatures" | "53-two-visible-signatures-annotation.pdf" | 2          | [PDF_ANNOTATION_CHANGES]
    }

    @Story("Change restricted by DocMDP produces warnings")
    def "Restricted change under DocMDP (#description) is reported as warnings"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(file))

        then: "signature passes with DocMDP restricted change warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings.content", containsInAnyOrder(*warnings))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))

        where:
        description                   | file                               | warnings
        "form field filled under P=1" | "21-docmdp-P1-form-filled.pdf"     | [PDF_DOCMDP_RESTRICTED_CHANGES]
        "annotation under P=1"        | "22-docmdp-P1-annotation.pdf"      | [PDF_DOCMDP_RESTRICTED_CHANGES, PDF_ANNOTATION_CHANGES]
        "content overlay under P=1"   | "23-docmdp-P1-content-overlay.pdf" | [PDF_DOCMDP_RESTRICTED_CHANGES, PDF_VISUAL_DIFFERENCE + "[1]", PDF_UNDEFINED_CHANGES]
        "annotation under P=2"        | "32-docmdp-P2-annotation.pdf"      | [PDF_DOCMDP_RESTRICTED_CHANGES, PDF_ANNOTATION_CHANGES]
        "content overlay under P=2"   | "33-docmdp-P2-content-overlay.pdf" | [PDF_DOCMDP_RESTRICTED_CHANGES, PDF_VISUAL_DIFFERENCE + "[1]", PDF_UNDEFINED_CHANGES]
    }

    @Story("Modification after document timestamp produces warnings")
    def "Modification after document timestamp (#description) is reported as warnings on PAdES LTA signature"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(file))

        then: "LTA signature passes with each modification warning reported twice"
        // Each warning appears twice: once from the signature, once from its document timestamp
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].signatureFormat", is(SignatureFormat.PAdES_BASELINE_LTA))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings.content", containsInAnyOrder(*(warnings + warnings)))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))

        where:
        description        | file                          | warnings
        "page added"       | "71-lta-page-added.pdf"       | [PDF_PAGE_COUNT_MISMATCH, PDF_ANNOTATION_CHANGES, PDF_UNDEFINED_CHANGES]
        "content overlaid" | "72-lta-content-overlay.pdf"  | [PDF_VISUAL_DIFFERENCE + "[1]", PDF_UNDEFINED_CHANGES]
        "annotation added" | "73-lta-annotation-added.pdf" | [PDF_ANNOTATION_CHANGES]
    }

    @Story("Modification after signing produces warnings under POLv3")
    def "Modification after signing (#description) is reported as warnings under POLv3 policy"() {
        when: "validation is requested with POLv3 policy"
        Response response = SivaRequests.validate(RequestData.validationRequest(file, SignaturePolicy.POLICY_3))

        then: "signature passes with modification warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings.content", containsInAnyOrder(*warnings))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))

        where:
        description                   | file                          | warnings
        "page added"                  | "03-page-added.pdf"           | [PDF_PAGE_COUNT_MISMATCH, PDF_ANNOTATION_CHANGES, PDF_UNDEFINED_CHANGES]
        "content overlaid"            | "01-content-overlay.pdf"      | [PDF_VISUAL_DIFFERENCE + "[1]", PDF_UNDEFINED_CHANGES]
        "annotation added"            | "05-annotation-overlay.pdf"   | [PDF_ANNOTATION_CHANGES]
        "annotation under DocMDP P=1" | "22-docmdp-P1-annotation.pdf" | [PDF_DOCMDP_RESTRICTED_CHANGES, PDF_ANNOTATION_CHANGES]
    }

    @Story("Co-signature of unmodified document keeps both signatures valid")
    def "Co-signature of unmodified document (#description) keeps both signatures valid without warnings"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(file))

        then: "both signatures pass without warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(2))
                .body("signaturesCount", is(2))

        where:
        description                       | file
        "invisible co-signature"          | "F00-cosigned-unmodified.pdf"
        "two visible signatures"          | "51-two-visible-signatures.pdf"
        "visible and invisible signature" | "52-visible-and-invisible-signature.pdf"
    }

    @Story("Modification before co-signature is reported on first signature only")
    def "Modification before co-signature (#description) is reported as warnings on first signature only"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest(file))

        then: "first signature passes with warnings, second signature passes without warnings"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings.content", containsInAnyOrder(*warnings))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(2))
                .body("signaturesCount", is(2))

        where:
        description                       | file                                  | warnings
        "content overlaid"                | "F01-cosigned-content-overlay.pdf"    | [PDF_VISUAL_DIFFERENCE + "[1]", PDF_UNDEFINED_CHANGES]
        "content replaced"                | "F02-cosigned-content-replaced.pdf"   | [PDF_VISUAL_DIFFERENCE + "[1]", PDF_UNDEFINED_CHANGES]
        "page added"                      | "F03-cosigned-page-added.pdf"         | [PDF_PAGE_COUNT_MISMATCH, PDF_ANNOTATION_CHANGES, PDF_UNDEFINED_CHANGES]
        "page removed"                    | "F04-cosigned-page-removed.pdf"       | [PDF_PAGE_COUNT_MISMATCH, PDF_ANNOTATION_CHANGES, PDF_UNDEFINED_CHANGES]
        "annotation over content"         | "F05-cosigned-annotation-overlay.pdf" | [PDF_ANNOTATION_CHANGES]
        "content overlaid by same signer" | "S01-same-signer-content-overlay.pdf" | [PDF_VISUAL_DIFFERENCE + "[1]", PDF_UNDEFINED_CHANGES]
        "page added by same signer"       | "S03-same-signer-page-added.pdf"      | [PDF_PAGE_COUNT_MISMATCH, PDF_ANNOTATION_CHANGES, PDF_UNDEFINED_CHANGES]
    }

    @Story("Visual comparison is skipped for documents over 10 pages")
    def "Content change in document over 10 pages is reported as undefined changes warning without visual difference"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest("81-eleven-pages-content-overlay.pdf"))

        then: "signature passes with undefined changes warning only"
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings.content", contains(PDF_UNDEFINED_CHANGES))
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }

    @Story("Locked field value change under FieldMDP is not detected")
    def "Locked form field value filled under FieldMDP is not reported"() {
        when: "validation is requested"
        Response response = SivaRequests.validate(RequestData.validationRequest("41-fieldmdp-locked-field-value-filled.pdf"))

        then: "signature passes without warnings"
        // Known DSS 6.2 limitation: a /V-only change carries no field name, so the FieldMDP and SigFieldLock
        // checks find no locked field to compare. If this starts failing, DSS now detects it - update the expectation.
        response.then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].warnings", emptyOrNullString())
                .body("validSignaturesCount", is(1))
                .body("signaturesCount", is(1))
    }
}