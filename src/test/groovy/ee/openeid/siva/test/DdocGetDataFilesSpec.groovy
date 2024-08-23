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
package ee.openeid.siva.test

import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link
import org.apache.http.HttpStatus
import org.hamcrest.Matchers
import spock.lang.Ignore

@Link("http://open-eid.github.io/SiVa/siva3/use_cases/#ddoc-data-file-extraction-process")
class DdocGetDataFilesSpec extends GenericSpecification {

    @Description("Valid DDOC with data file used")
    def "testGetDataFileFromValidDdoc"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequest("18912.ddoc"))
                .then()
                .body("dataFiles[0].filename", Matchers.is("readme"))
                .body("dataFiles[0].mimeType", Matchers.is("text/plain"))
                .body("dataFiles[0].base64", Matchers.startsWith("RGlnaURvYyBpcyBhIGdlbmVyaWMgbGlicmFyeSBp"))
                .body("dataFiles[0].size", Matchers.is(491))
    }

    @Description("Invalid DDOC with data file used")
    def "testGetDataFileFromInvalidDdoc"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequest("OCSP nonce vale.ddoc"))
                .then()
                .body("dataFiles[0].filename", Matchers.is("testfail.txt"))
                .body("dataFiles[0].mimeType", Matchers.is("text/plain"))
                .body("dataFiles[0].base64", Matchers.is("T2xlbiB0ZXN0IGZhaWwu"))
                .body("dataFiles[0].size", Matchers.is(15))
    }

    @Description("DDOC with xml v1.1 is  used")
    def "testGetDataFileFromDdocXml1_0"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequest("SK-XML1.0.ddoc"))
                .then()
                .body("dataFiles[0].filename", Matchers.is("Tartu ja Tallinna koostooleping.doc"))
                .body("dataFiles[0].mimeType", Matchers.is("application/msword"))
                .body("dataFiles[0].base64", Matchers.startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAAUgAAAAAAAAAA"))
                .body("dataFiles[0].size", Matchers.is(44544))
    }

    @Description("DDOC with xml v1.1 is  used")
    def "testGetDataFileFromDdocXml1_1"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequest("DIGIDOC-XML1.1.ddoc"))
                .then()
                .body("dataFiles[0].filename", Matchers.is("puhkus_urmo_062006.doc"))
                .body("dataFiles[0].mimeType", Matchers.is("application/msword"))
                .body("dataFiles[0].base64", Matchers.startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAAJAAAA"))
                .body("dataFiles[0].size", Matchers.is(549376))
    }

    @Description("DDOC with xml v1.2 is  used")
    def "testGetDataFileFromDdocXml1_2"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequest("DIGIDOC-XML1.2.ddoc"))
                .then()
                .body("dataFiles[0].filename", Matchers.is("RO219559508.pdf"))
                .body("dataFiles[0].mimeType", Matchers.is("text/text"))
                .body("dataFiles[0].base64", Matchers.startsWith("JVBERi0xLjMKJeLjz9MKMSAwIG9iajw8L1Byb2R1Y2VyKGh0bWxkb2MgMS44LjIzIENvcHlyaWdodCAxOTk3LTIwMDI"))
                .body("dataFiles[0].size", Matchers.is(3938))
    }

    @Description("DDOC with xml v1.3 is  used")
    def "testGetDataFileFromDdocXml1_3"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequest("valid_XML1_3.ddoc"))
                .then()
                .body("dataFiles[0].filename", Matchers.is("test.txt"))
                .body("dataFiles[0].mimeType", Matchers.is("application/octet-stream"))
                .body("dataFiles[0].base64", Matchers.startsWith("VGVzdCBhbmQgc29tZSBvdGhlciB0ZXN0"))
                .body("dataFiles[0].size", Matchers.is(24))
    }

    @Ignore("SIVA-376")
    @Description("Hashcoded DDOC  is  used")
    def "testGetDataFileFromDdocHashcoded"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequest("DIGIDOC-XML1.3_hashcode.ddoc"))
                .then()
                .body("dataFiles[0].filename", Matchers.is("Glitter-rock-4_gallery.jpg"))
                .body("dataFiles[0].mimeType", Matchers.is("application/octet-stream"))
                .body("dataFiles[0].base64", Matchers.nullValue())
                .body("dataFiles[0].size", Matchers.is(41114))
    }

    @Description("DDOC  with 12 different  files of different types  is  used")
    def "testGetMultipileDataFilesFromDdoc"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequest("igasugust1.3.ddoc"))
                .then()
                .body("dataFiles[0].filename", Matchers.is("DigiDocService_spec_1_110_est.pdf"))
                .body("dataFiles[0].mimeType", Matchers.is("application/pdf"))
                .body("dataFiles[0].base64", Matchers.startsWith("JVBERi0xLjMKJcfsj6IKOCAwIG9iago8PC9MZW5ndGggOSAwIFIvRmlsdGVyIC9G"))
                .body("dataFiles[0].size", Matchers.is(435164))
                .body("dataFiles[1].filename", Matchers.is("Testilood20070320.doc"))
                .body("dataFiles[1].mimeType", Matchers.is("application/msword"))
                .body("dataFiles[1].base64", Matchers.startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAAEAAAA"))
                .body("dataFiles[1].size", Matchers.is(222720))
                .body("dataFiles[2].filename", Matchers.is("fail.rtf"))
                .body("dataFiles[2].mimeType", Matchers.is("application/msword"))
                .body("dataFiles[2].base64", Matchers.startsWith("e1xydGYxXGFuc2lcZGVmZjBcYWRlZmxhbmcxMDI1CntcZm9udHRibHtcZjBcZnJv"))
                .body("dataFiles[2].size", Matchers.is(2145))
                .body("dataFiles[3].filename", Matchers.is("fail.odt"))
                .body("dataFiles[3].mimeType", Matchers.is("application/unknown"))
                .body("dataFiles[3].base64", Matchers.startsWith("UEsDBBQAAAAAAJhRwTpexjIMJwAAACcAAAAIAAAAbWltZXR5cGVhcHBsaWNhdGlv"))
                .body("dataFiles[3].size", Matchers.is(7427))
                .body("dataFiles[4].filename", Matchers.is("4.txt"))
                .body("dataFiles[4].mimeType", Matchers.is("text/plain"))
                .body("dataFiles[4].base64", Matchers.startsWith("/GtzZmFpbA=="))
                .body("dataFiles[4].size", Matchers.is(7))
                .body("dataFiles[5].filename", Matchers.is("kolm.doc"))
                .body("dataFiles[5].mimeType", Matchers.is("application/msword"))
                .body("dataFiles[5].base64", Matchers.startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAA"))
                .body("dataFiles[5].size", Matchers.is(24064))
                .body("dataFiles[6].filename", Matchers.is("5.xls"))
                .body("dataFiles[6].mimeType", Matchers.is("application/vnd.ms-excel"))
                .body("dataFiles[6].base64", Matchers.startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAA"))
                .body("dataFiles[6].size", Matchers.is(14848))
                .body("dataFiles[7].filename", Matchers.is("kaks.doc"))
                .body("dataFiles[7].mimeType", Matchers.is("application/msword"))
                .body("dataFiles[7].base64", Matchers.startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAA"))
                .body("dataFiles[7].size", Matchers.is(24064))
                .body("dataFiles[8].filename", Matchers.is("kõõs.txt"))
                .body("dataFiles[8].mimeType", Matchers.is("text/plain"))
                .body("dataFiles[8].base64", Matchers.is("bfZoaGho"))
                .body("dataFiles[8].size", Matchers.is(6))
                .body("dataFiles[9].filename", Matchers.is("yks.doc"))
                .body("dataFiles[9].mimeType", Matchers.is("application/msword"))
                .body("dataFiles[9].base64", Matchers.startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAA"))
                .body("dataFiles[9].size", Matchers.is(24064))
                .body("dataFiles[10].filename", Matchers.is("testid.txt"))
                .body("dataFiles[10].mimeType", Matchers.is("text/plain"))
                .body("dataFiles[10].base64", Matchers.startsWith("UElOMSBibG9raXM6DQoNCjI1MTMNCjI1MjMNCjI1MjcNCjI1MzENCjI1NTkNCj"))
                .body("dataFiles[10].size", Matchers.is(414))
                .body("dataFiles[11].filename", Matchers.is("NsPdf.PDF"))
                .body("dataFiles[11].mimeType", Matchers.is("application/pdf"))
                .body("dataFiles[11].base64", Matchers.startsWith("JVBERi0xLjMKJeTjz9IKNSAwIG9iago8PC9MZW5ndGggNiAwIFIKL0ZpbHRlci9GbGF0ZURlY29"))
                .body("dataFiles[11].size", Matchers.is(2783))
    }

    @Description("BDOC with data file used")
    def "testGetDataFileFromBdocShouldFail"() {
        expect:
        SivaRequests.tryGetDataFiles(RequestData.dataFileRequest("BDOC-TS.bdoc"))
                .then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].message", Matchers.is("Invalid filename. Can only return data files for DDOC type containers."))
                .body("requestErrors[0].key", Matchers.is("filename"))
    }

    @Description("PDF file used")
    def "testGetDataFileFromPdfShouldFail"() {
        expect:
        SivaRequests.tryGetDataFiles(RequestData.dataFileRequest("hellopades-lt-b.pdf"))
                .then()
                .statusCode(HttpStatus.SC_BAD_REQUEST)
                .body("requestErrors[0].message", Matchers.is("Invalid filename. Can only return data files for DDOC type containers."))
                .body("requestErrors[0].key", Matchers.is("filename"))
    }
}
